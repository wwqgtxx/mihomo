<h1 align="center">
  <img src="https://github.com/metacubex/mihomo/raw/master/docs/logo.png" alt="Mihomo" width="200">
  <br>Mihomo<br>
</h1>

<h4 align="center">A rule-based tunnel in Go.</h4>

<p align="center">
  <a href="https://github.com/metacubex/mihomo/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Dreamacro/mihomo/release.yml?branch=master&style=flat-square" alt="Github Actions">
  </a>
  <a href="https://goreportcard.com/report/github.com/metacubex/mihomo">
    <img src="https://goreportcard.com/badge/github.com/metacubex/mihomo?style=flat-square">
  </a>
  <img src="https://img.shields.io/github/go-mod/go-version/Dreamacro/mihomo?style=flat-square">
  <a href="https://github.com/metacubex/mihomo/releases">
    <img src="https://img.shields.io/github/release/Dreamacro/mihomo/all.svg?style=flat-square">
  </a>
  <a href="https://github.com/metacubex/mihomo/releases/tag/premium">
    <img src="https://img.shields.io/badge/release-Premium-00b4f0?style=flat-square">
  </a>
</p>

## Features

- Local HTTP/HTTPS/SOCKS server with authentication support
- Shadowsocks(R), VMess, Trojan, Snell, SOCKS5, HTTP(S) outbound support
- Built-in [fake-ip](https://www.rfc-editor.org/rfc/rfc3089) DNS server that aims to minimize DNS pollution attack impact. DoH/DoT upstream supported.
- Rules based off domains, GEOIP, IP-CIDR or process names to route packets to different destinations
- Proxy groups allow users to implement powerful rules. Supports automatic fallback, load balancing or auto select proxy based off latency
- Remote providers, allowing users to get proxy lists remotely instead of hardcoding in config
- Transparent proxy: Redirect TCP and TProxy TCP/UDP with automatic route table/rule management
- Hot-reload via the comprehensive HTTP RESTful API controller

## Premium

Premium core is proprietary. You can find their release notes and pre-built binaries [here](https://github.com/metacubex/mihomo/releases/tag/premium).

- gvisor/system stack TUN device on macOS, Linux and Windows ([ref](https://github.com/metacubex/mihomo/wiki/Mihomo-Premium-Features#tun-device))
- Policy routing with [Scripts](https://github.com/metacubex/mihomo/wiki/Mihomo-Premium-Features#script)
- Load your rules with [Rule Providers](https://github.com/metacubex/mihomo/wiki/Mihomo-Premium-Features#rule-providers)
- Monitor Mihomo usage with a built-in profiling engine. ([Dreamacro/mihomo-tracing](https://github.com/metacubex/mihomo-tracing))

## Getting Started
Documentations are available at [GitHub Wiki](https://github.com/metacubex/mihomo/wiki).

## Development
If you want to build a Go application that uses Mihomo as a library, check out the [GitHub Wiki](https://github.com/metacubex/mihomo/wiki/Using-Mihomo-in-your-Golang-program).

## Credits

* [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
* [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
* [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)

## License

This software is released under the GPL-3.0 license.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FDreamacro%2Fmihomo.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FDreamacro%2Fmihomo?ref=badge_large)
