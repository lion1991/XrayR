# XrayR

[![](https://img.shields.io/badge/TgChat-@XrayR讨论-blue.svg)](https://t.me/XrayR_project)
[![](https://img.shields.io/badge/Channel-@XrayR通知-blue.svg)](https://t.me/XrayR_channel)
![](https://img.shields.io/github/stars/XrayR-project/XrayR)
![](https://img.shields.io/github/forks/XrayR-project/XrayR)
![](https://github.com/XrayR-project/XrayR/actions/workflows/release.yml/badge.svg)
![](https://github.com/XrayR-project/XrayR/actions/workflows/docker.yml/badge.svg)
[![Github All Releases](https://img.shields.io/github/downloads/XrayR-project/XrayR/total.svg)]()


[English](https://github.com/XrayR-project/XrayR/blob/master/README-en.md)|[Iranian](https://github.com/XrayR-project/XrayR/blob/master/README_Fa.md)|[Vietnamese](https://github.com/XrayR-project/XrayR/blob/master/README-vi.md)

A Xray backend framework that can easily support many panels.

一个基于Xray的后端框架，支持 V2ray/Vmess/Vless、Trojan、Shadowsocks、AnyTLS、Hysteria/Hysteria2 (hy2)、Snell (v5/v6) 协议，极易扩展，支持多面板对接。

如果您喜欢本项目，可以右上角点个star+watch，持续关注本项目的进展。

使用教程：[详细使用教程](https://xrayr-project.github.io/XrayR-doc/)


## 免责声明

本项目只是本人个人学习开发并维护，本人不保证任何可用性，也不对使用本软件造成的任何后果负责。

## 特点

* 永久开源且免费。
* 支持 V2ray/Vmess/Vless、Trojan、Shadowsocks、AnyTLS、Hysteria/Hysteria2 (hy2)、Snell (v5/v6) 等多种协议。
* 支持 Vless/XTLS/REALITY 等新特性。
* AnyTLS/Snell 使用 sing-box 控制器（不经过 xray 分发器，故不支持按用户限速/设备数限制/审计规则）。
* 支持单实例对接多面板、多节点，无需重复启动。
* 支持限制在线IP
* 支持节点端口级别、用户级别限速。
* 配置简单明了。
* 修改配置自动重启实例。
* 方便编译和升级，可以快速更新核心版本， 支持Xray-core新特性。

## 功能介绍

| 功能        | v2ray | trojan | shadowsocks |
|-----------|-------|--------|-------------|
| 获取节点信息    | √     | √      | √           |
| 获取用户信息    | √     | √      | √           |
| 用户流量统计    | √     | √      | √           |
| 服务器信息上报   | √     | √      | √           |
| 自动申请tls证书 | √     | √      | √           |
| 自动续签tls证书 | √     | √      | √           |
| 在线人数统计    | √     | √      | √           |
| 在线用户限制    | √     | √      | √           |
| 审计规则      | √     | √      | √           |
| 节点端口限速    | √     | √      | √           |
| 按照用户限速    | √     | √      | √           |
| 自定义DNS    | √     | √      | √           |

说明：AnyTLS/Snell 由 sing-box 控制器提供支持，功能覆盖以面板下发配置及 sing-box 能力为准。

### Snell 的两种用户模式（部署前必读）

Snell 把每用户密钥放在协议的 ClientID 字段里，而官方 Surge 客户端**没有**设置 client-id 的配置项。因此下面两种模式**不可兼得**，由面板 `protocol_settings.multi_user` 决定：

| `multi_user` | 官方 Surge 客户端 | 按用户计流量 / 限速 / 封禁 |
|---|---|---|
| `false`（默认） | ✅ 可连接 | ❌ 无法识别用户，流量上报恒为 0；踢人需给所有人换 psk |
| `true` | ❌ 连不上（空 client-id 会被拒） | ✅ 用户 uuid 即为密钥，正常计费 |

XrayR 只能服务 Snell v5 / v6；v3、v4 请继续使用外部 snell-server。v6 的 psk 长度必须为 12–255 字节。

注意：**v5 不能开 `multi_user`** —— Surge 能连 v5 但发不出 client-id，而能发 client-id 的 sing-box 系客户端又没有实现 v5 客户端，这个组合开出来的节点没有任何客户端连得上。XrayR 会在启动时直接报错拒绝。要多用户计费请用 v6。

## 支持前端

| 前端                                                     | v2ray | trojan | shadowsocks             |
|--------------------------------------------------------|-------|--------|-------------------------|
| keeper (V2board 兼容)                                   | √     | √      | √                       |

说明：AnyTLS/Hysteria/Hysteria2/Snell 当前通过 keeper（UniProxy API）下发配置；其它面板请以实际支持为准。

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/XrayR-project/XrayR-release/master/install.sh && bash install.sh
```

### 使用Docker部署软件

[Docker部署教程](https://xrayr-project.github.io/XrayR-doc/xrayr-xia-zai-he-an-zhuang/install/docker)

### 手动安装

[手动安装教程](https://xrayr-project.github.io/XrayR-doc/xrayr-xia-zai-he-an-zhuang/install/manual)

## 配置文件及详细使用教程

[详细使用教程](https://xrayr-project.github.io/XrayR-doc/)

## Thanks

* [Project X](https://github.com/XTLS/)
* [V2Fly](https://github.com/v2fly)
* [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
* [Air-Universe](https://github.com/crossfw/Air-Universe)

## Licence

[Mozilla Public License Version 2.0](https://github.com/XrayR-project/XrayR/blob/master/LICENSE)

## Telgram

[XrayR后端讨论](https://t.me/XrayR_project)

[XrayR通知](https://t.me/XrayR_channel)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/XrayR-project/XrayR.svg)](https://starchart.cc/XrayR-project/XrayR)
