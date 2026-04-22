# nmesh
A simple, high-performance decentralized VPN.

## Build

```bash
git submodule update --init
make

```

## Configure

Create `nmesh.conf`:

```ini
# Required: overlay IPv6 address (must be in fe80::/96).
address = fe80::1

# Required: pre-shared key (32-byte raw string or 64-hex).
psk = your_psk

# Optional: TAP interface name (default: nmesh).
ifname = nmesh

# Optional: listen port (default: 50000).
port = 50000

# Optional: overlay MTU (default: 1280, valid range: 128..65535).
mtu = 1280

# Optional: PMTU probing (default: disable).
mtu_probe = disable

# Optional: P2P behavior (default: enable).
p2p = enable

# Optional: tap data path mode (default: auto).
# auto: single CPU -> inline, otherwise -> pipe
# inline: TAP handled in main event loop thread
# pipe: TAP handled by tap pipeline worker threads
tap_mode = auto

# Optional and repeatable: static bootstrap peers.
peer = 203.0.113.1:50000
# peer = [2001:db8::1]:50000

# Optional and repeatable: bogon filter rules.
# bogon = 10.0.0.0/8
# bogon = fc00::/7

```

## Run

```bash
sudo ./build/release/nmesh -c nmesh.conf

```

## Performance

|  | UDP (Gbps) | TCP (Gbps) |
| --- | --- | --- |
| nmesh | 3.263 | 8.517 |
| nebula 1.10.3 | 1.543 | 1.263 |
| wireguard-go v0.0.20250522 | 0.880 | 6.533 |

Local environment:

- Linux `6.6.123.2-microsoft-standard-WSL2+` on `x86_64`
- CPU: AMD Ryzen 9 7940HX with Radeon Graphics

These numbers are a point-in-time local reference, not a portability claim.


## Planned Features

- [WIP] Data Channel Offload support for better performance.

## Acknowledgements

- [Tailscale](https://github.com/tailscale/tailscale), whose userspace GSO/GRO work informed this project's packet-path design.
- [EtherGuard-VPN](https://github.com/KusakabeShi/EtherGuard-VPN), whose one-way delay routing design informed this project's route selection rules.
