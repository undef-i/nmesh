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
ifname = nmesh
address = fe80::1
listen = 50000
mtu = 1280
mtu_probe = disable
psk = your_psk
peer = 203.0.113.1:50000

```
`address` must be in the `fe80::/96` prefix.

## Run

```bash
sudo ./build/release/nmesh -c nmesh.conf

```

## Performance

Local baseline on commit `10f93764a0cf157692e4dc526bf261762b1e9de1`:

| Metric | Result |
| --- | --- |
| UDP | 4.58 Gbits/sec, 4.7% loss |
| TCP | 7.93 Gbits/sec, 0 retransmits |

Local environment:

- Linux `6.6.123.2-microsoft-standard-WSL2+` on `x86_64`
- CPU: AMD Ryzen 9 7940HX with Radeon Graphics

These numbers are a point-in-time local reference, not a portability claim.

## Known Issues

- Fails if underlying MTU is below 128 bytes.

## Planned Features

- [WIP] Data Channel Offload support for better performance.

## Acknowledgements

- [Tailscale](https://github.com/tailscale/tailscale), whose userspace GSO/GRO work informed this project's packet-path design.
- [EtherGuard-VPN](https://github.com/KusakabeShi/EtherGuard-VPN), whose one-way delay routing design informed this project's route selection rules.
