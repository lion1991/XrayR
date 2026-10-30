# 0001 服务端只用 wkernel（sing-box）一个内核

Status: Accepted（2026-10-29），实施方案见 `docs/plans/sing-box-migration.md`

## 背景

XrayR 同时跑 Xray-core（VMess / VLESS / Reality / Trojan / SS / Hysteria2）和上游 sing-box（AnyTLS / Snell），要追两个内核，还维护一份分叉的 Xray dispatcher。客户端全部用 wkernel（自维护的 sing-box 分支），Xray 独有的能力（xhttp、Reality mldsa65 等）客户端本来就用不上。

## 决定

- 服务端只依赖 wkernel，通过 `go.mod` 的 `replace` 引入（wkernel 的 module 名仍是 `github.com/sagernet/sing-box`）；删除 Xray-core 和 `app/mydispatcher`。
- 用户热更新做成 wkernel 的服务端补丁（用户 key 改为用户名），登记在 wkernel 的上游同步文档里，每次同步都要检查。
- 设备数、限速、审计在 XrayR 自己包装的 direct 出站里拨号前完成，不改 wkernel 的连接追踪器。
- 每个节点一个 box；不加内核选择开关，灰度靠先部署一台服务器，回滚靠重新部署旧镜像。
- 放弃 Xray 独有的服务端能力（清单见方案第 1 节），删除 `dns.json` / `route.json` / 自定义入站出站这四个 Xray 格式的本地配置，改为代码里默认屏蔽私有 IP 和 BT。
- 删除用户时立即断开其现有连接。
- CI 继续在 GitHub Actions 构建，用 Wkernel 仓库上的只读 deploy key 拉取。

## 否决的方案

- 给 CI 的 deploy key 写权限：私钥在公开仓库的 CI 里，泄露即可往所有客户端的内核投毒。
- 把 XrayR 构建搬到 Forgejo，或把 wkernel 镜像到 GitHub：都要多存一个凭据，还要改服务器拉取地址或维护同步链路。仅当 GitHub 构建机连不上 `git.wrlog.cn:2222` 时再考虑镜像到 GitHub。
- 在 sing-box 节点上监听 `::`：所有节点目前没有 IPv6，等加了 IPv6 再做。

## 后果

- wkernel 多了服务端补丁，跟随上游 alpha 同步时冲突面变大。
- XrayR 是公开仓库但依赖私有的 wkernel，外人克隆后无法编译。
- 面板里依赖 Xray `tcp:host:port` 匹配格式的审计规则需要调整为按域名匹配。
