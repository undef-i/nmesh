# nmesh
A simple, decentralized VPN.

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
frag = disable
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

