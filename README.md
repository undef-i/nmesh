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
psk = your_psk
peer = 203.0.113.1:11451

```

## Run

```bash
sudo ./build/release/nmesh -c nmesh.conf

```

## Known Issues

- Physical link MTU values below `128` are not supported.

