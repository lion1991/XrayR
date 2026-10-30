# 主内核从 Xray-core 迁到 sing-box（wkernel）

Status: 已定，实施中（W1、W2、S1–S4、P1 已完成，下一步 P2）。架构决策见 `docs/adr/0001-sing-box-as-sole-kernel.md`。

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
   - 已实测（2026-10-30，Actions run 41002508939）：GitHub 构建机能直接连上 `git.wrlog.cn:2222`，不需要把 wkernel 镜像到 GitHub。

## 2. 架构取舍（已定，供审阅）

- **每个节点一个 box**：沿用现有 `SingBoxController` 的做法，不改成全进程共享一个 box。这样做故障隔离好，也是已有代码路径。节点配置变化（端口、传输、TLS）时只重建这个节点的 box；用户变化走热更新，不断连接。证书续期不用重建 box：TCP 上的 TLS 入站会监视证书文件并自动重载；QUIC（Hysteria）只在监听时读一次证书，续期后要重建（见 P1）。
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
  - 审计沿用 Xray 的匹配字符串 `tcp:host:port`，拨号地址和 sniff 到的域名（`metadata.Domain`）各匹配一次，任一命中就拒绝（细节见 S3c），面板规则不用调整（S3c 实施时改定；原方案是只匹配域名、调整面板规则）。要拿到域名，节点必须开启路由 sniff（受 `DisableSniffing` 控制）。
  - UDP 的限制：XUDP / packetaddr 一条连接里可以有多个目标，只能按第一个目标做审计。
- **监听和出站地址**：`ListenIP` 原样传给 sing-box。所有节点目前都没有 IPv6（用户确认），`0.0.0.0` 只监听 IPv4 不影响使用，所以不做 `::` 映射；以后节点加了 IPv6 再改。`SendIP` 是 `0.0.0.0` 时当作没设置。`DNSType` 映射到 `domain_resolver.strategy`，旧的 `domain_strategy` 已废弃。
- **构建 tag**（S1 已定）：只加 `with_utls`（Reality 需要），写在 `release/build_tags`，Dockerfile 和 `scripts/verify.sh` 都读这个文件。
  - 不加 `with_quic`：XrayR 直接注册 hysteria / hysteria2 入站，不经过 sing-box 的 `include` 注册表，`with_quic` 只影响那个注册表、v2ray QUIC 传输和 HTTP/3。
  - 不加 `with_grpc`：wkernel 客户端的构建也不带，两端都用 lite 实现。
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
- **W2** ✅ 打发布 tag `v1.15.0-alpha.13-w.1`（在 wkernel `1416c013` 上），供 XrayR 依赖。命名用 `-w.<序号>` 而不是 `-w`：wkernel 同步上游时按 `v*-w` 找上次同步点，非合并提交上的 `-w` tag 会让基线算错（规则见 wkernel `docs/wkernel-upstream-sync.md` §7）。wkernel 的 `go.mod` 没有 `replace`，可以直接当依赖模块用。

### 阶段 1：补齐 sing-box 控制器（AnyTLS / Snell 节点立即受益）

- **S1** 把 XrayR 依赖的 sing-box 换成 wkernel（`replace`），接通 CI 拉取；加上构建 tag。验证：编译，跑 `snell_e2e_test.go` 等现有测试。

  已完成（XrayR `9747f06`）。在 `s1-wkernel` 分支手动触发 CI，构建通过，镜像为 `ghcr.io/lion1991/xrayr:s1-wkernel`，`latest` 没动。做法：
  - `replace github.com/sagernet/sing-box => git.wrlog.cn/lion1991/Wkernel.git <tag>`。路径带 `.git` 后缀，Go 直接走 git，不依赖 Forgejo 的 go-get 页面；`https://git.wrlog.cn/` 由 git 的 insteadOf 改写成 `ssh://git@git.wrlog.cn:2222/`。
  - CI 把 deploy key 装进 ssh-agent，转发给 BuildKit（`RUN --mount=type=ssh`）。主机公钥固定在 `release/known_hosts`。
  - 依赖下载和编译放在同一个 `RUN` 里，模块缓存用 cache mount：工作流把中间层导出到公开仓库的 Actions 缓存，wkernel 源码不能落进任何一层。
  - 本机开发：`scripts/verify.sh` 自带 `GOPRIVATE` 和 insteadOf 改写；直接跑 `go` 命令且模块缓存里还没有 wkernel 时，需要自己设这两项。
  - CI 只在构建前一步把 key 装进 agent，构建完就结束 agent；`.dockerignore` 排除 `.git`，因为 checkout 会把 GITHUB_TOKEN 写进 `.git/config`。
  - 代价：模块缓存不进层，CI 每次都要重新下载全部模块、从头编译，构建会慢几分钟。接受这个代价。
  - alpha.3 → alpha.13 没有引起编译错误，但 sing-anytls 升级后去掉了重复密码检查，后写入的会覆盖前一个，两个用户的流量会记到同一个人名下。所以在 controller 里统一做了检查：有空密码或重复密码就拒绝启动节点，和升级前一样。S2 做热更新时再改成跳过有问题的用户并告警。
  - 还要确认一件事：到服务器上核对 Forgejo 的 SSH 主机公钥指纹，应为 `SHA256:YIMbYkHUTBIZUHcRaOd/FYeBON7Pu0qocBofnSzOOGk`（RSA 4096）。`release/known_hosts` 里的公钥也是经代理取到的。
- **S2** 用户热更新：定时拉取用户列表，按 UID 区分增删和属性变化，属性变化只更新 limiter。节点信息变化时重建 box。每次拉取时刷新 jitter（现在只在启动时读一次）。调用 `UpdateUsers` 前去重、校验，列表没变就不调（见 W1 的约束）。UUID 或密码变了但名字没变时，按删除再添加处理，并且要断开旧连接，否则旧凭据的会话会以同一个名字继续通过。snell 节点在没有用户时不建入站，等有了用户再重建 box。决定 3 要的断开放到 S3 做，因为需要连接登记表。

  已完成（回归用例 `service/controller/singbox_update_e2e_test.go`、`snell_e2e_test.go`）。落地后的行为：
  - 节点信息和用户列表各自拉取，拉取失败或返回未变化都沿用上次的期望状态。去掉了 sing-box 控制器的心跳任务：它会消耗 keeper 的 ETag，让下一次真正的拉取拿到 304。
  - 用户增删、换密码都在原 box 上调 `UpdateUsers`，已有连接不断。hysteria v1 没有热更新接口，用户变化时重建 box。属性变化目前什么都不做，S3 有了 limiter 再接上。
  - 节点信息有任何变化（`reflect.DeepEqual`，和 Xray 控制器一样）就重建 box，现有连接会断开。新配置被 sing-box 拒绝时旧 box 继续服务，用户变化照常应用到旧 box 上，错误每轮记一次日志。
  - 有问题的用户跳过并告警，不再拒绝整个节点：UID 重复留第一个；密码为空跳过；多个用户共用一个密码时全部跳过，因为流量分不清是谁的。告警内容不变就不重复打。
  - 没有可用用户时不建入站，有了再建。keeper 对空列表返回 "users is null" 错误（常量 `api.UserListEmpty`），这时 ETag 已经前进，sing-box 控制器把它当作空列表处理，所以删掉最后一个用户会关掉节点。Xray 控制器没改，仍然是旧行为。
  - 流量计数器按连接上的用户名记，box 重建后保留，用户被删后已有连接的流量照样上报。上报时按 UID 合并，因为 keeper 按 UID 建表，重复的 UID 会覆盖前一条。
  - 已知遗留：计数器表只增不减（每个出现过的用户名一条，量很小）；节点信息里和 sing-box 无关的字段变化（比如 DNS 配置）也会重建 box。
- **S3** 管控：包装出站（设备数、限速、审计）；连接追踪器负责流量计数和连接登记；删除用户时断开现有连接，出站包装还要拒绝不在当前用户列表里的用户（已认证的会话会继续开新流）；在线 IP 按存活连接统计并上报（现在只统计新建连接，长连接用户会漏报）；定时拉取审计规则；自动限速。把 `singbox_traffic.go` 里每条连接一条的 Info 日志降级，UDP 日志里写死的 "AnyTLS" 也改掉。

  分四步提交，每步可单独回滚：S3a 断开被删用户；S3b 设备数、限速和在线 IP；S3c 审计规则（连同它依赖的 sniff）；S3d 自动限速和日志降级。

  S3a 已完成（回归用例 `TestSingBoxNodeFollowsPanelChanges`、`TestGuardAdmitsOnlyServedUsers`、`TestUserNamesFollowCredentialChanges`）：
  - 节点的默认出站换成 `singbox_guard.go` 里的 `xrayr-direct`：它嵌入 direct 出站，wkernel 按 `Type()` 判断 direct 的地方行为不变。拨号前先查用户是否还在名单里，再登记连接，`onClose` 时注销。
  - 原地更新用户前先放行新旧名单的并集，避免新用户的第一条连接被拒；更新成功后收紧到新名单，并断开名单外用户的连接。重建 box 时，在启动前换名单。
  - 断开时先设一个已过期的 deadline，再调 Close。只调 Close 不够：snell 的 reuse 连接回过数据后，Close 只做半关闭，客户端的上传会继续送到目标，直到目标再写数据才停（e2e 实测过）。
  - 用户名改成 `tag|email|uid|版本`。同一个 UID 的密码或 UUID 变了，版本号就加一，用旧凭据认证的会话名字不再被放行，所以换密码等同于删除再添加，旧连接会断。版本号在控制器运行期间保留，用户被删后再加回来也不会复用旧名字。
  - 改了 email 的用户名字也会变，也会被断开一次。很少发生，不做特殊处理。
  - 已知遗留：被拒的连接没有日志，追踪器还会先打一条这个用户的 Info 连接日志，S3d 降级日志时一并处理。
  - e2e 只能验证已建立的连接被关闭；“已认证的会话开不了新流”需要多路复用的客户端，由单测 `TestGuardAdmitsOnlyServedUsers` 覆盖。

  S3b 已完成（回归用例 `TestSingBoxNodeLimitsAndReportsOnline`、`TestGuardDeviceLimit`、`TestGuardSpeedLimit`、`TestWaitTokensSplitsLargeReads`、`TestRateConnHalfCloses`、`TestAddDevice`）：
  - 限速和设备数都由 guard 在拨号前决定。限速和设备数来自 keeper 的本地配置 `SpeedLimit` / `DeviceLimit`，用户限速也可以来自面板的 `speed_limit`，节点限速和用户限速取更严的。只改限速或设备数时，不重建 box、不断连接。
  - 设备 = 上次在线上报后建过连接的 IP，和 Xray 一样。超出设备数的新 IP 被拒，已知 IP 不受影响；断开的设备要等下次上报才让出名额。
  - 存活连接不占设备名额。review 时考虑过让它占名额，不采用：手机从 WiFi 切到 4G 后，旧 IP 上的死连接要等 TCP keepalive（5 分钟起，最长十几分钟）才断，设备数为 1 的用户会被锁在外面这么久。代价和 Xray 一样：上报后另一台设备可以抢走长连接设备的名额，之后长连接设备的新连接被拒。
  - 在线 IP 上报 = 上报周期内见过的 IP ∪ 有存活连接的 IP，每个流量周期报一次，长连接用户不再漏报。
  - 跨节点设备数（Redis，`GlobalDeviceLimitConfig`）从 `common/limiter` 抽成 `GlobalLimiter`，两套控制器共用，key 格式不变（`设备数|email|uid`），所以 Xray 节点和 sing-box 节点按同一份名单计数。sing-box 侧只在设了设备数时才访问 Redis。缓存出错的日志改走 logrus。顺手修了上游的计数 bug（Xray 节点也受益）：原来先判断 `已有 IP 数 > 设备数` 再加入，会多放进一台设备，之后连已有设备也全部被拒，直到 key 过期；现在已知 IP 总是放行，新 IP 在 `已有 IP 数 >= 设备数` 时被拒（`TestAddDevice`）。Xray 侧被全局检查拒掉的新 IP 也从本地在线名单里删掉，不再占本地名额、不再被上报在线（原来只有本地拒绝才删；这一处没有单测，Redis 部分需要真实 Redis）。
  - 已知未修（上游原样，概率低）：写 Redis 是异步的整表覆盖，两台新设备同时上线会丢掉一个；sing-box 侧写入 Redis 后，如果本地复查时用户刚被删或名额被抢，这个 IP 会在 Redis 里白占一个名额直到过期。
  - 限速：每个 UID 一个令牌桶，上下行共用，容量为一秒的量（和 Xray 一样）。一次读写超过桶容量时分段等待：`WaitN` 遇到超过容量的请求会直接报错，Xray 的实现在这种情况下会放过整块数据不限速。
  - 只有建连时有限速的用户才包装连接，没限速的用户走原来的拷贝路径。包装层转发 `CloseWrite`（和拷贝一样先越过下面的流量计数层），不把半关闭变成全关闭（snell v5 靠它告诉客户端目标为什么断开；`TestRateConnHalfCloses`）。限速被取消时，令牌桶改成不限，已有连接立即生效；没限速的用户新加了限速，S3d 起会断开他未包装的现有连接（见 S3d）。
  - 已知未修：限速等待中的连接关闭后要等这段等待结束才释放（有界，不会卡死）。
  - 已核对：sing 的拷贝只在包装层声明可替换时才拆包装，splice 只用于 TUN，所以限速包装不会被零拷贝绕过（第 4 节的待实测项已有结论）。

  S3c 已完成（回归用例 `TestSingBoxNodeAudits`、`TestAuditTargets`、keeper 的 `TestCompileRuleSkipsWhatBreaksTheNode`）：
  - 默认路由加一条无条件的 sniff 规则，`DisableSniffing` 关掉，和 Xray 节点默认开 sniff 一致（原定在 S4 做，审计依赖它，提前到这里）。sniff 只填 `metadata.Domain`，不改拨号目标。代价：服务器先发数据的协议（SSH 等）和不带换行的首包建连时最多多等 sniff 超时（300ms），Xray 节点同样如此。wkernel 对邮件端口（25/465/587/143/993/110/995）跳过 sniff，所以这些端口上的 TLS 只能按 IP 审计，Xray 会 sniff。
  - 匹配串整体转小写：Xray 的 HTTP sniff 会把 Host 转小写，sing 不会，大写 Host 会绕过规则；面板规则按小写写。UDP over TCP（AnyTLS 的 UDP 都走它）在 `metadata.Domain` 里留的是魔法域名 `sp.v2.udp-over-tcp.arpa`，审计时忽略它，按真实目标匹配。旧版 UoT（`sp.udp-over-tcp.arpa`）的目标逐包携带，连接上只有 `0.0.0.0:0`，和 XUDP 一样审计不到。这两点由 `TestAuditTargets` 覆盖；UoT 没有 e2e（snell v6 + UoT 会让进程崩溃，是 wkernel 侧的已有问题，另行处理）。
  - 拨号地址和 sniff 到的域名各生成一个匹配串，任一命中就拒绝。Xray 会改成按 sniff 到的域名拨号，一个串就够；sing 仍拨原地址，只看域名的话，客户端用允许的 SNI / Host 就能连被封的地址。代价是比 Xray 严：封了某个 IP，经这个 IP 访问允许的域名也会被拒。
  - 审计在 guard 里、设备数检查之前做，对所有连接生效（包括没有用户的 shared-psk snell）。命中只拒绝并打 Warn 日志，不记录违规：keeper 的违规上报是空实现（见上）。命中的 Warn 由 S3d 限频（见 S3d）。
  - 规则每个拉取周期在拉完节点信息后拉一次（keeper 从节点信息里取规则），`DisableGetRule` 关掉。面板清空规则时节点上的规则也清空；Xray 侧原来只在规则非空时更新，删光规则后旧规则一直生效，一并修了。
  - keeper 顺手修（Xray 节点也受益）：面板或本地规则文件里的正则写错会让进程 panic，空规则或空的备选项（比如没填匹配项的 block 路由、匹配项里有空串时拼出的 `a.com|`、规则文件里的空行）会匹配所有目标、拒绝全部流量，现在逐项包成 `(?:…)` 编译（避免 `(?i)`、未闭合的 `\Q` 影响其他项），写错的项和能匹配空串的项（空白、`.*`、`^`、`foo|` 等）单独去掉并打日志，同一条路由里其余的项照常生效（写错的项每次拉取都会报一次，直到面板改好）；规则 ID 改用面板路由的 id，原来是它在列表里的下标；本地规则列表不再被每次拉取的 append 共用底层数组。
  S3d 已完成（回归用例 `TestSingBoxNodeAutoLimitsFastUsers`、`TestAutoSpeedLimit`、`TestGuardCutsUnlimitedConnectionsOnNewLimit`、`TestGuardThrottlesRejectionLogs`）：
  - 自动限速沿用 `AutoSpeedLimitConfig`，语义同 Xray：一次上报里上行或下行超过 `Limit`，连续超过 `WarnTimes` 次后限到 `LimitSpeed`，`LimitDuration` 分钟后恢复；`Limit` 或 `LimitSpeed` 为 0 时不启用。和 Xray 的不同：速率按实际计入的时长算（Xray 按 `UpdatePeriodic` 算，上报抖动和上报失败都会算偏）；状态按 UID 记（Xray 按整个用户信息记，面板改了用户任何字段就丢状态）；自动限速和面板限速取更严的（Xray 直接覆盖，可能把更严的面板限速放宽）。限住和恢复各打一条 Info。已知偏差：面板上报失败时计数不清零，下一次按更长的时长重算同一批流量，"连续超限"的次数会算上重叠的数据（Xray 按固定周期算累计流量，偏得更多）。
  - 用户从不限速变成限速（自动限速、面板新加限速、节点新加限速）时，guard 断开他未包装的现有连接，客户端重连后就受限：未包装的连接没法事后限速。代价：被限的用户掉线重连一次；节点新加限速时全节点重连一次。已在令牌桶里的连接只改速率，不断开。
  - 日志：每条连接、每个用户每次的流量日志降到 Debug，UDP 日志里写死的 "AnyTLS" 改成实际入站类型；超设备数的 Warn 每个 UID 每分钟最多一条（本节点和跨节点共用一个名额），审计命中的 Warn 每个 UID 每条规则每分钟最多一条；限频用独立的锁，不占 guard 的主锁；已删除用户被拒只打 Debug。
- **S4** 出站和日志：`SendIP`、`DNSType`、日志级别和错误日志映射（现在 sing-box 控制器把日志整个关掉了）；默认屏蔽私有 IP 和 BT（决定 2）。BT 识别依赖 sniff（S3c 已开）。
  - 日志：`Log.Level` 映射成 sing-box 的日志级别（`none` 或不填仍是关闭，`warning` → `warn`），`ErrorPath` 作为输出文件，`AccessPath` 没有对应（决定 1）。sing-box 在 info 级别会每条连接打一行，和 Xray 的 info 一样多。`Level: debug` 时 XrayR 自己的日志也降到 Debug 级别（以前 Level 只管 Xray，XrayR 的 Debug 日志永远不显示），其他级别 XrayR 仍打 Info。
  - 出站：`SendIP` 设成 direct 出站的源地址（IPv4 设 inet4、IPv6 设 inet6），空或未指定地址（`0.0.0.0`、`::`）不绑定；格式错误时节点启动失败。`DNSType` 按 Xray freedom 的读法映射成解析策略（`UseIPv4` → `ipv4_only`、`UseIPv4v6` → `prefer_ipv4`，`AsIs` / `UseIP` → 两种都要），只在 `EnableDNS` 时生效；认不出的值节点启动失败。节点用一个本机 DNS（系统解析器）。
  - 屏蔽私有地址：路由在 sniff 之后按上面的策略解析域名，guard 在拨号前检查。direct 只拨解析出的那组地址，所以域名只有全部解析结果都是公网才放行（覆盖 `localhost` 和"一半公网一半内网"的域名）。拒绝发生在设备数检查之前，不占名额，只打 Debug。
    - 私有范围照 Xray 的 `geoip:private`（含 `0.0.0.0/8`、CGNAT `100.64.0.0/10`、`198.18.0.0/15`、`240.0.0.0/4` 等），不用 sing-box 的 `ip_is_private`：它漏掉 CGNAT（阿里云元数据 `100.100.100.200`、Tailscale）这些段。另加 NAT64（`64:ff9b::/96`、`64:ff9b:1::/48`）和 IPv4 兼容地址（`::/96`）。判断前先去掉 IPv6 zone：`::%0` 这种写法按域名类型发来会被解析成带 zone 的地址，任何网段都不包含它，内核却照样当本机。
    - 不拦服务器自己的公网 IP（Xray 的 `geoip:private` 也不拦）：绑在 0.0.0.0、只靠云安全组或针对外网网卡的防火墙挡住的服务，用户连"服务器公网 IP:端口"仍能从本机访问到。用户决定不加（2026-10-30）：不把本机网卡地址加进屏蔽集合。
    - `0.0.0.0` / `::` 是私有：内核把它当本机，TCP 连 `0.0.0.0:6379` 就是连本机 Redis。唯一的例外是目标就是未指定地址的包连接——legacy UoT 路由时没有目标——放进来后每个包再查。
    - 包连接（XUDP、UoT）里每个包都查：IP 直接判断，域名先查一次本机 DNS，结果全是公网才放行。direct 会再解析一次，两次之间 DNS 答案变了（DNS rebinding）能绕过，已知未修。
    - 测试要连本机的回显服务，用只在测试里可见的开关关掉这项检查，其余规则不变。
  - 屏蔽 BT：只拦 TCP 握手（`network: tcp` + `protocol: bittorrent`，要开 sniff）。sing-box 的 uTP 嗅探会把 WireGuard 握手（`01 00 00 00` 开头）和 RakNet ping 判成 BitTorrent，Xray 的 uTP 嗅探实际从不命中，所以 Xray 节点一直只拦 TCP。
  - 日志量：sing-box 把扫描器的握手失败、认证失败、拨号失败都记成 ERROR（Xray 记在 Info），`Level: warning` 下 ErrorPath 会比 Xray 时期多出这些行。
  - `SendIP` 只绑一个协议族，另一族从系统默认地址出去（Xray 的 Go dialer 会只用 SendIP 那一族）；节点都没有 IPv6，暂不处理。Xray 的 `origin` / `srcip` 写法不支持，节点启动报错。
  - 代码里构造的拒绝规则必须显式写 `method: default`：JSON 解析才会补默认值，空的 method 一命中路由就 panic。

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

- **P1** Trojan（已完成）：keeper 的 Trojan 节点固定是 tcp + TLS，用户密钥用 UUID（keeper 不给 Trojan 发 Passwd，和 Xray 一致），用户变化热更新不重建。
  - 其他传输（ws / grpc 等）和 REALITY 节点启动报错，留到 P4 / P5。`EnableFallback` 打警告后忽略（决定 1）；`EnableProxyProtocol` 对所有 sing-box 节点都打警告后忽略。Xray 的 mux.cool 不支持，wkernel 客户端用不上。
  - `CertMode: none` 照 Xray 提供明文 Trojan（TLS 由前置代理卸载）；AnyTLS 没有明文形式，仍报错。ALPN 照 Xray 服务端默认协商 `h2, http/1.1`，主动探测看到的 TLS 表现不变。
  - 证书续期：以前 sing-box 控制器不续期，dns / http 模式的证书约 90 天后过期（AnyTLS 节点一直有这个问题）。现在和 Xray 一样每 60×`UpdatePeriodic` 秒调一次续期，新文件由 sing-box 重载；Hysteria 节点续期成功后重建 box。
  - wkernel 的证书重载有竞争：证书和私钥两个回调并发执行，两边都可能配出"新证书 + 旧私钥"，重载失败后旧证书一直用到过期。已在 wkernel `65c53531` 修复（本地提交，未推送）；XrayR 升级到含该提交的版本之前续期仍可能不生效，`TestTrojanNodeReloadsCertificate` 也先跳过，升级时去掉跳过。
  - 依赖：trojan 入站引入 v2ray 传输的间接依赖（`gobwas/httphead`、`gobwas/pool`、`sagernet/ws`）。

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
- ~~S3 实测：限速包装会不会被 splice / 零拷贝绕过。~~ S3b 已核对，不会（见 S3b）。
- hysteria2 的热更新依赖 sing-quic 的 `UpdateUsers`，它发布用户表时没有同步，是数据竞争。现在镜像只构建 amd64，实际不会出错。上 arm64 之前，必须先在 sing-quic 里改成原子存储。
- sing-snell v6 的数据竞争（上游，S4 的测试暴露）：连接在服务端第一次回复前关闭时，`CloseWrite` 在锁内写 `session.writer`，另一个拷贝方向的 `FrontHeadroom` 不加锁读它。远端没回包就断开的 Snell UDP / UoT 连接都会碰到，`TestSingBoxNodeBlocksPrivateAndBitTorrent` 在 `-race` 下基本每次都会报出，跑 race 时先 `-skip` 它。根治要在 sing-snell 里给 `FrontHeadroom` 加锁或改成原子读。
- 热更新会重建 snell 服务，两个副作用：
  - snell v5 的 salt 过滤器被清空，历史抓包的首包可以再重放一次；
  - 每个服务带约 6MB 过滤器，有长连接挂在旧服务上时释放不了。
  根治要在 sing-snell 里把用户表改成原子存储，就不用重建服务。S2 只在变化时更新，可以把影响压到很小。
- mylego 的老问题（Xray 控制器同样存在，不在本方案内修）：tls 模式续期要监听 :443，节点自己占着 443 时每次续期都失败；同一进程多个节点共用一个域名时会并发续期、交错写同一组文件，可能写出不配对的证书和私钥；`CertDomain` 含大写时续期结果写到另一个文件，节点读不到。
- 已知的遗留问题，不在本方案内修：Xray 控制器上 keeper 的空用户列表会被当成拉取失败，删掉节点最后一个用户永远不生效；被删用户最后一个周期的流量不会上报。sing-box 控制器在 S2 里已经处理了这两点，Xray 控制器迁移完会删除。
