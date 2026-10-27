# nmesh
A decentralized VPN.

## Build

```bash
git submodule update --init
make

```

## Configure

See `nmesh.conf.example`.

## Run

```bash
sudo ./build/release/nmesh -c nmesh.conf
sudo ./build/release/nmesh status

```

## Planned Features

- [ ] Data Channel Offload support
- [ ] UDP path forward secrecy via ephemeral ECDH rekey

## Acknowledgements

- [Go Implementation of WireGuard](https://github.com/WireGuard/wireguard-go), whose userspace GSO/GRO work informed this project's packet-path design.
