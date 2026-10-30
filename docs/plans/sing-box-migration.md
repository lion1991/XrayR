# 主内核从 Xray-core 迁到 sing-box（wkernel）

Status: 已定，实施中（W1 已完成，下一步 W2）。架构决策见 `docs/adr/0001-sing-box-as-sole-kernel.md`。

## 背景与目标

- 现状：VMess / VLESS（含 Reality）/ Trojan / Shadowsocks / Hysteria2 走 Xray-core（`service/controller/controller.go`），AnyTLS、Snell 走上游 sing-box（`singbox_controller.go`，依赖 v1.15.0-alpha.3）。要同时追两个内核，Xray 侧还维护着一份分叉的 dispatcher（`app/mydispatcher`）。
- 客户端统一用 wkernel（`../wkernel`，sing-box 分支，当前 `v1.15.0-alpha.13-w`，module 名仍是 `github.com/sagernet/sing-box`）。
- 目标：服务端只依赖 wkernel 一个内核，两端协议实现同源；删除 Xray-core 依赖和 `app/mydispatcher`。
- 不做：改动面板（keeper）协议；新增客户端功能。

## 1. 已定的决定（2026-10-29 用户确认）

1. **放弃以下 Xray 独有能力**（用户确认都没在用）。wkernel 客户端本来就用不上的标 ★，其余只影响服务端：
   - ★ xhttp / splithttp 传输
   - ★ Reality 的 `Mldsa65Seed`、`MinClientVer` / `MaxClientVer`
   - Reality 的 `Show`、`Xver`（回落目标的 PROXY protocol）、`LimitFallbackUpload/Download`；`ServerNames` 只保留第一个（sing-box 的 Reality 只接受单个 server_name）
   - `EnableFallback` / `FallBackConfigs`（VLESS 无回落；Trojan 只有单一回落和按 ALPN 回落）
   - `EnableProxyProtocol`（sing-box 1.6 起已移除入站 PROXY protocol）
   - TCP 传输的 HTTP 头伪装（`Header`），包括 keeper 给 SS 节点配 obfs=http 的情况（目前没有节点在用）
   - `ConnectionConfig`（握手超时、连接空闲 30s 断开、单向超时、缓冲区大小）：sing-box 没有 TCP 空闲超时
   - `CertConfig.RejectUnknownSni`、OCSP stapling
   - Log 的 `AccessPath`（访问日志）。日志级别和错误日志会映射过去
   - WebSocket 传输的 Host 校验（sing-box 的 ws 服务端不校验 Host，httpupgrade 校验）
   - 以下不算放弃，属于直接删除的死代码：`Shadowsocks-Plugin`（keeper 不支持这个类型）、`DisableIVCheck`（现在已经不起作用）
2. **删除节点本地的 `dns.json` / `route.json` / `custom_inbound.json` / `custom_outbound.json`**：这四个是 Xray 格式的文件，sing-box 不需要，用户确认不再保留。删掉 `DnsConfigPath` 等四个配置项和读取代码，不做 sing-box 格式的替代配置（原 S5 取消），`release/config/` 下的示例文件和 geoip/geosite.dat 一并删除。
   - sing-box 节点在代码里**默认屏蔽访问私有 IP 和 BT**（`ip_is_private`、`protocol: bittorrent` → reject），不加配置项。原因：没配 route.json 的节点现在不屏蔽，用户可以借节点访问服务器本机或内网服务（比如设备数限制用的 Redis），BT 会招来版权投诉。
3. **删除用户时立即断开该用户的现有连接**。Xray 现在的行为是删除用户后已建立的连接还能继续用，直到客户端断开。增删按 UID 判断，面板只改了限速或设备数的用户不会被断开。
4. **CI 拉取 wkernel 的凭据**（已定、已配好）。XrayR 继续在 GitHub Actions 构建、推 ghcr.io，不搬到 Forgejo，也不把 wkernel 镜像到 GitHub（两者都要多存一个凭据，服务器拉取地址或同步链路还得跟着变）。凭据是 Wkernel 仓库上的 deploy key `xrayr-github-ci`，**只读**：私钥存 XrayR 的 Actions secret `WKERNEL_DEPLOY_KEY`，本机副本在 `~/.ssh/wkernel_deploy`。已实测能读、写被拒。
   - 否决：给这把 key 写权限。私钥在公开仓库的 CI 里，泄露即可往所有客户端的内核投毒；以后真要 CI 写 wkernel，另加一把 key。
   - 待 S1 实测：GitHub 构建机能否连上 `git.wrlog.cn:2222`；连不上再改为把 wkernel 镜像到 GitHub 私有仓库。

## 2. 架构取舍（已定，供审阅）

- **每个节点一个 box**：沿用现有 `SingBoxController` 的做法，不改成全进程共享一个 box。这样做故障隔离好，也是已有代码路径。节点配置变化（端口、传输、TLS）时只重建这个节点的 box；用户变化走热更新，不断连接。证书续期不用重建 box，sing-box 会监视证书文件并自动重载。
- **用户热更新放进 wkernel（W1）**：vmess / vless / trojan / snell / hysteria2 现在认证后只返回用户下标，入站再拿下标去查用户列表。在这种结构下直接替换列表有竞态：正在建立的连接会按新列表取名，流量记到别人头上，列表变短时还会越界 panic。
  - 改法：用户 key 直接用用户名（和 anytls 已有的 `MultiService[string]` 一样）。
  - Shadowsocks 复用它已经导出的 `adapter.ManagedSSMServer`。
  - Shadowsocks 和 Snell 在用户列表为空时会退化成共享密钥模式，任何拿到密钥的人都能连上而且不计流量。热更新路径上必须防住这一点：SS 设 `Managed: true`，Snell 拒绝空列表。

  这是服务端专用补丁，要写进 wkernel 的上游同步文档，作为每次同步都要检查的冲突点。
- **拒绝和限速放在 XrayR 自己的出站里，不放在连接追踪器里**：wkernel 的 `ConnectionTracker` 在拨号之前被调用，但只能包装连接，不能返回错误，所以拒绝不了；等到要拒绝时远端已经连上了。改成在 XrayR 里实现一个包装 direct 的出站（实现 `adapter.ConnectionHandler` / `PacketConnectionHandler`），在拨号前完成以下检查，不需要改 wkernel：
  - 设备数检查
  - 限速
  - 审计规则

  连接追踪器只负责流量计数和按用户登记存活连接，供决定 3 的断开和在线 IP 统计用。
  - `common/limiter`、`common/rule` 里的 Xray 依赖（`errors`、`common`、`buf`）换成标准库，`rate.go` 改成包装 net.Conn / PacketConn。
  - 审计改为匹配 `metadata.Domain`。Xray 匹配的是 `tcp:host:port` 这种字符串，依赖这个格式的面板规则要调整。要拿到域名，节点必须开启路由 sniff（受 `DisableSniffing` 控制）。
  - UDP 的限制：XUDP / packetaddr 一条连接里可以有多个目标，只能按第一个目标做审计。
- **监听和出站地址**：`ListenIP` 原样传给 sing-box。所有节点目前都没有 IPv6（用户确认），`0.0.0.0` 只监听 IPv4 不影响使用，所以不做 `::` 映射；以后节点加了 IPv6 再改。`SendIP` 是 `0.0.0.0` 时当作没设置。`DNSType` 映射到 `domain_resolver.strategy`，旧的 `domain_strategy` 已废弃。
- **构建 tag**：Reality 需要 `with_utls`，QUIC 系协议要确认是否需要 `with_quic`，gRPC 按需加 `with_grpc`。不加的话 gRPC 走 lite 实现。S1 把这些 tag 写进 Dockerfile 和验证脚本，e2e 测试也要带上。
- **不加内核选择开关**：灰度时把新镜像先部署到一台服务器上，回滚就是重新部署旧镜像。
- **不做的上报**：keeper 的节点状态上报和违规上报都是空实现，不往 sing-box 侧移植；删除 Xray 时连同 `common/serverstatus` 一起删掉。在线 IP 上报照做。

## 3. 分阶段步骤

每一步对应一个提交，能单独回滚（`git revert` 该提交并重新部署上一个镜像）。每做完一步停下来汇报。

### 阶段 W：wkernel 侧

- **W1** 运行时用户替换：覆盖 vmess / vless / trojan / hysteria2 / anytls / snell，用户 key 改为用户名；Shadowsocks 对齐 `ManagedSSMServer`；空列表不能退化。单测要覆盖三种情况：
  - 替换过程中已有连接不断；
  - 替换和认证同时发生时用户名不会错位；
  - 替换成空列表时不能退化成共享密钥模式。

  在 `docs/wkernel-upstream-sync.md` 里登记这个补丁。

  已完成（wkernel `1416c013`，回归用例 `test/inbound_user_update_test.go`）。落地时定下的、XrayR 侧要遵守的约束：
  - 用户名是唯一身份，必须非空且唯一（现有的 `tag|email|uid` 满足）。
  - 已认证的会话在用户被删后还能开新流（mux、hysteria2、anytls、snell reuse），入站侧拦不住，由 S3 的出站包装拒绝。
  - 更新是全有或全无：一个坏用户（重复密码、空 key）会让整批失败，被删的用户继续能连。所以调用前要先去重和校验。
  - vmess 的防重放表和 snell v5 的 salt 过滤器每次更新都会清空，只在列表真的变化时调用。
  - snell 入站在创建时如果没有用户，就固定为单 PSK 模式，之后不能再加用户。
  - 调用必须串行。
- **W2** 打 `-w` tag，供 XrayR 依赖。

### 阶段 1：补齐 sing-box 控制器（AnyTLS / Snell 节点立即受益）

- **S1** 把 XrayR 依赖的 sing-box 换成 wkernel（`replace`），接通 CI 拉取；加上构建 tag。验证：编译，跑 `snell_e2e_test.go` 等现有测试。
- **S2** 用户热更新：定时拉取用户列表，按 UID 区分增删和属性变化，属性变化只更新 limiter。节点信息变化时重建 box。每次拉取时刷新 jitter（现在只在启动时读一次）。调用 `UpdateUsers` 前去重、校验，列表没变就不调（见 W1 的约束）。UUID 或密码变了但名字没变时，按删除再添加处理，并且要断开旧连接，否则旧凭据的会话会以同一个名字继续通过。snell 节点在没有用户时不建入站，等有了用户再重建 box。决定 3 要的断开放到 S3 做，因为需要连接登记表。
- **S3** 管控：包装出站（设备数、限速、审计）；连接追踪器负责流量计数和连接登记；删除用户时断开现有连接，出站包装还要拒绝不在当前用户列表里的用户（已认证的会话会继续开新流）；在线 IP 按存活连接统计并上报（现在只统计新建连接，长连接用户会漏报）；定时拉取审计规则；自动限速。把 `singbox_traffic.go` 里每条连接一条的 Info 日志降级，UDP 日志里写死的 "AnyTLS" 也改掉。
- **S4** 出站和日志：`SendIP`、`DNSType`、默认路由 sniff、日志级别和错误日志映射（现在 sing-box 控制器把日志整个关掉了）；默认屏蔽私有 IP 和 BT（决定 2）。BT 识别依赖 sniff。

完成后 AnyTLS 和 Snell 节点的功能与 Xray 节点持平。部署一台服务器自用验证，再全量。

### 阶段 2：逐个协议迁移

把 `panel.go` 里分流到 sing-box 的协议名单逐个扩大，每个协议一步：先在 builder 里实现，再加进程内 e2e 测试（参照 `snell_e2e_test.go`，用 wkernel 自己的 outbound 当客户端），然后灰度一台服务器。

| 步骤 | 协议 | 要点 |
|---|---|---|
| P1 | Trojan | TLS 证书来自 CertConfig |
| P2 | Shadowsocks | 含 SS2022 多用户（`ServerKey` + 用户 PSK）；面板配了 obfs=http 时节点启动报错，不静默降级 |
| P3 | Hysteria2 | 从 Xray 移回 sing-box；obfs、带宽沿用旧 sing-box 实现。version 不是 2 时直接拒绝（现在的 sing-box 代码遇到 version 为 0 会按 Hysteria 1 启动） |
| P4 | VMess / VLESS | tcp / ws / grpc / httpupgrade；VLESS flow |
| P5 | VLESS Reality + Vision | 映射 Reality 字段：`MaxTimeDiff` 的毫秒值要转成 Duration，本地 `REALITYConfigs` / `DisableLocalREALITYConfig` 两条路径都要处理，Reality 节点不要求 CertConfig。按决定 1 放弃的字段遇到时打警告。e2e 测试替代 `reality_smoke_test.go` |

每步都要验证：e2e 测试通过；灰度服务器的流量上报、在线 IP、限速和 Xray 时期一致；CPU 和吞吐不明显变差。

### 阶段 3：删除 Xray

- **R0** 先把 sing-box 控制器还在借用的代码搬到独立文件，再动删除：
  - `periodicTask`、`compareUserList`（`controller.go`）
  - `getCertFile`（`inboundbuilder.go`）
  - Xray 的 `common/task`，换成自有的定时任务实现
- **R1** 删除以下内容：
  - `app/mydispatcher`
  - `controller.go` / `control.go` / `inboundbuilder.go` / `outboundbuilder.go` / `userbuilder.go`，以及依赖它们的测试
  - `panel.go` 里的 Xray 实例和全局配置，包括 `DnsConfigPath` / `RouteConfigPath` / `InboundConfigPath` / `OutboundConfigPath`（决定 2）
  - `common/serverstatus`、`cmd/mldsa65.go`、`cmd/distro/all`
- **R2** `api` 包去掉 Xray 类型：`NodeInfo.NameServerConfig`（面板下发的 `dns` 路由现在没有被使用，直接删掉）、`HttpHeaders` 里的 `conf.StringList`、`keeper.go` 引用的 `net` / `conf`。
- **R3** 清理 go.mod，更新 README、示例配置（删除 `release/config/` 下四个 json 和 geoip/geosite.dat）和本文档状态。跑全部回归用例。

## 4. 风险与待实测

- wkernel 跟随上游 alpha，内部 API 经常变（v1.14 起就遇到过证书注册表变化）。服务端补丁会增加每次同步的冲突面。缓解办法：补丁尽量集中在一个接口上，同步验收清单里加上服务端 e2e 测试。
- Reality 和 Vision 两端实现不同（Xray 和 sing-box），P5 是迁移后才首次由 wkernel 同源服务。要先在自己的设备上长时间使用，再全量。
- S3 实测：限速包装会不会被 splice / 零拷贝绕过。
- hysteria2 的热更新依赖 sing-quic 的 `UpdateUsers`，它发布用户表时没有同步，是数据竞争。现在镜像只构建 amd64，实际不会出错。上 arm64 之前，必须先在 sing-quic 里改成原子存储。
- 热更新会重建 snell 服务，两个副作用：
  - snell v5 的 salt 过滤器被清空，历史抓包的首包可以再重放一次；
  - 每个服务带约 6MB 过滤器，有长连接挂在旧服务上时释放不了。
  根治要在 sing-snell 里把用户表改成原子存储，就不用重建服务。S2 只在变化时更新，可以把影响压到很小。
- 已知的遗留问题，不在本方案内修：keeper 遇到空用户列表直接报错，所以删掉节点最后一个用户永远不生效；被删用户最后一个周期的流量不会上报（两套控制器都这样）。
