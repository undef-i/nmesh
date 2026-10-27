# nmesh
A decentralized VPN.

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

# Optional: overlay MTU (default: 65511, range: 128..65511).
mtu = 65511

# Optional: physical MTU upper bound (default: 0, meaning auto-detect).
# When set, caps the path MTU to this value regardless of interface scanning.
default_phys_mtu = 1280

# Optional: path MTU probing (default: disable).
mtu_probe = enable

# Optional: transport preference, comma-separated (udp, tcp).
transport = udp,tcp

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

# Optional: authentication mode (default: psk).
# auth = ibs
# ibs_mpk = <master public key>
# ibs_sk = <node secret key>

```

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
