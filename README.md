# Doctor Mobile — mihomo fork

This is the Doctor Mobile fork of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo),
built and shipped ourselves so our app owns its VPN core. Based on the official
release **v1.19.29**. Development happens on the [`doctormobile`](../../tree/doctormobile) branch.

### Our changes
- **Opt-in public-domain DNS validation**: append `#dm-public-ip=true` to
  nameservers used by a public-domain `nameserver-policy` (or append
  `&dm-public-ip=true` after an existing fragment). Private, loopback, and fake
  A/AAAA replies cannot win the parallel resolver pool; negative and alias-only
  replies wait for competing address answers, then remain valid if none exists.
  Use `direct-nameserver-follow-policy: true` to apply the same policy to DIRECT
  lookups. Do not enable this option on LAN or intentionally private split-DNS
  policies. Servers without the option retain upstream behavior.
- **`tun(android)`: don't fail TUN start when `packages.xml` is unreadable**
  ([`2e34689`](../../commit/2e34689)) — mihomo runs as an unprivileged VpnService
  subprocess, so it cannot read `/data/system/packages.xml` for per-app rules
  (which we don't use: `auto-route` and `find-process-mode` are off). Upstream
  treated that read error as fatal, aborting the whole TUN and dropping all
  device traffic. We degrade gracefully (warn + skip) instead.
- **`anytls`: support `reality-opts`** ([`fc21579`](../../commit/fc21579)) —
  upstream mihomo's `AnyTLSOption` has no REALITY, so anytls+REALITY nodes could
  never connect. The TLS path anytls already uses supports REALITY, so we just
  expose `reality-opts` and wire it through.
- **CI**: [`android-dm.yml`](../../blob/doctormobile/.github/workflows/android-dm.yml)
  builds `libmihomo.so` for android arm64 / armv7 / x86_64.

---

<h1 align="center">
  <img src="Meta.png" alt="Meta Kennel" width="200">
  <br>Meta Kernel<br>
</h1>

<h3 align="center">Another Mihomo Kernel.</h3>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/MetaCubeX/mihomo">
    <img src="https://goreportcard.com/badge/github.com/MetaCubeX/mihomo?style=flat-square">
  </a>
  <img src="https://img.shields.io/github/go-mod/go-version/MetaCubeX/mihomo/Alpha?style=flat-square">
  <a href="https://github.com/MetaCubeX/mihomo/releases">
    <img src="https://img.shields.io/github/release/MetaCubeX/mihomo/all.svg?style=flat-square">
  </a>
  <a href="https://github.com/MetaCubeX/mihomo">
    <img src="https://img.shields.io/badge/release-Meta-00b4f0?style=flat-square">
  </a>
</p>

## Features

- Local HTTP/HTTPS/SOCKS server with authentication support
- VMess, VLESS, Shadowsocks, Trojan, Snell, TUIC, Hysteria protocol support
- Built-in DNS server that aims to minimize DNS pollution attack impact, supports DoH/DoT upstream and fake IP.
- Rules based off domains, GEOIP, IPCIDR or Process to forward packets to different nodes
- Remote groups allow users to implement powerful rules. Supports automatic fallback, load balancing or auto select node
  based off latency
- Remote providers, allowing users to get node lists remotely instead of hard-coding in config
- Netfilter TCP redirecting. Deploy Mihomo on your Internet gateway with `iptables`.
- Comprehensive HTTP RESTful API controller

## Dashboard

A web dashboard with first-class support for this project has been created; it can be checked out at [metacubexd](https://github.com/MetaCubeX/metacubexd).

## Configration example

Configuration example is located at [/docs/config.yaml](https://github.com/MetaCubeX/mihomo/blob/Alpha/docs/config.yaml).

## Docs

Documentation can be found in [mihomo Docs](https://wiki.metacubex.one/).

## For development

Requirements:
[Go 1.20 or newer](https://go.dev/dl/)

Build mihomo:

```shell
git clone https://github.com/MetaCubeX/mihomo.git
cd mihomo && go mod download
go build
```

Set go proxy if a connection to GitHub is not possible:

```shell
go env -w GOPROXY=https://goproxy.io,direct
```

Build with gvisor tun stack:

```shell
go build -tags with_gvisor
```

### IPTABLES configuration

Work on Linux OS which supported `iptables`

```yaml
# Enable the TPROXY listener
tproxy-port: 9898

iptables:
  enable: true # default is false
  inbound-interface: eth0 # detect the inbound interface, default is 'lo'
```

## Debugging

Check [wiki](https://wiki.metacubex.one/api/#debug) to get an instruction on using debug
API.

## Credits

- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

## License

This software is released under the GPL-3.0 license.

**In addition, any downstream projects not affiliated with `MetaCubeX` shall not contain the word `mihomo` in their names.**
