# Packaging and deployment

Drop-in files for running `bcr` as a managed system service.

| File | Installs to | Purpose |
| --- | --- | --- |
| `systemd/bcr.service` | `/etc/systemd/system/bcr.service` | systemd unit (runs as root, lets `bcr` drop to `nobody`) |
| `bcr.default` | `/etc/default/bcr` | interface selection + extra options for the unit |
| `bcr.8` | `/usr/share/man/man8/bcr.8` | manual page |

> **Key behavior to know:** `bcr` has **no default config path**. Without `-c`
> it calls an internal allow-all and relays *every* broadcast/multicast packet.
> There is no implicit `/etc/bcr.conf`. The unit therefore passes
> `-c /etc/bcr.conf` **explicitly** — that is the only reason the deployed
> service gets filtered, deny-by-default behavior. Keep that flag in
> `ExecStart`; do not move it into `BCR_OPTS` where it could be dropped.

## Install walkthrough

```bash
# 1. Build and install the binary. The unit expects it at /usr/bin/bcr;
#    adjust ExecStart if you install elsewhere.
cargo build --release
sudo install -m 0755 target/release/bcr /usr/bin/bcr

# 2. Install a configuration file at the path the unit references. There is no
#    default — this file is only read because the unit passes `-c`.
sudo install -m 0644 examples/sample.conf /etc/bcr.conf
sudo $EDITOR /etc/bcr.conf          # tighten it to only what you need

# 3. Install the man page.
sudo install -m 0644 packaging/bcr.8 /usr/share/man/man8/bcr.8

# 4. Install the environment file and set your interfaces.
sudo install -m 0644 packaging/bcr.default /etc/default/bcr
sudo $EDITOR /etc/default/bcr        # set BCR_INPUT / BCR_OUTPUT

# 5. Install and enable the unit.
sudo install -m 0644 packaging/systemd/bcr.service /etc/systemd/system/bcr.service
sudo systemctl daemon-reload
sudo systemctl enable --now bcr.service

# 6. Verify.
sudo systemctl status bcr.service
journalctl -u bcr.service -f        # bcr logs one line per relayed packet
man 8 bcr
```

## How privileges work under systemd

`bcr` needs root to create its `AF_PACKET` sockets, so the unit runs as root
(no `User=`). It then drops to `nobody` itself (override with `-u <user>` in
`BCR_OPTS`). The unit restricts the capabilities root may use to
`CAP_NET_RAW` (sockets) plus `CAP_SETUID`/`CAP_SETGID` (the drop), and applies
the usual systemd sandboxing. Do **not** add `User=` to the unit — that would
strip the root needed for socket creation and `bcr` would refuse to start.

## Reloading config

`bcr` reads its config once at startup; there is no hot reload. After editing
`/etc/bcr.conf` (or `/etc/default/bcr`), restart the service:

```bash
sudo systemctl restart bcr.service
```

Because parsing is strict, a bad edit fails the restart loudly (check
`journalctl -u bcr.service`) rather than silently relaying the wrong traffic.
