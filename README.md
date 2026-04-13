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
listen = 11451
mtu = 1280
mtu_probe = disable
bogon = 172.16.0.0/12
bogon = 192.168.0.0/16
bogon = 10.0.0.0/8
bogon = 0.0.0.0/8
bogon = 100.64.0.0/10
bogon = 192.0.0.0/24
bogon = 192.0.2.0/24
bogon = 192.88.99.0/24
bogon = 198.18.0.0/15
bogon = 198.51.100.0/24
bogon = 203.0.113.0/24
bogon = 127.0.0.0/8
bogon = 169.254.0.0/16
bogon = 224.0.0.0/4
bogon = 240.0.0.0/4
bogon = ::
bogon = ::1
bogon = 100::/64
bogon = 2001:2::/48
bogon = 2001:10::/28
bogon = 2001:db8::/32
bogon = 2002::/16
bogon = 2001::/40
bogon = 2001:0:c000:2::/56
bogon = 2001:0:c0a8::/48
bogon = ff00::/8
bogon = fe80::/10
bogon = fec0::/10
bogon = fc00::/7
psk = your_psk
peer = 203.0.113.1:11451

```
`address` must be in the `fe80::/96` prefix.

## Run

```bash
sudo ./build/release/nmesh -c nmesh.conf

```


## Known Issues

- Fails if underlying MTU is below 128 bytes.


## Planned Features

- [WIP] Data Channel Offload support for better performance.
