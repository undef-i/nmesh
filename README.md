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
address = fe80::1
listen = 11451
mtu = 1280
psk = your_psk
peer = 203.0.113.1:11451

```
`address` must be in the `fe80::/96` prefix.

## Run

```bash
sudo ./build/release/nmesh -c nmesh.conf

```

## Known Issues

- Physical link MTU values below `128` are not supported.
- `mtu` config controls only the `nmesh` TAP interface MTU, not protocol packet sizing logic.
- TAP IPv6 address binding is intentionally configured as `/96` (for example `fe80::113/96`) to match nmesh LLA derivation from destination MAC tail; this prevents kernel routing from injecting out-of-model `/64` traffic into TAP.

