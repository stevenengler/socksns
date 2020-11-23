# socksns

[![Latest Version]][crates.io]

**Note:** This tool is a proof-of-concept and the code is terrible.

This tool will run a program in an isolated network namespace, and allow the program to connect only to a single TCP port such as a SOCKS proxy.

#### Installation:

```
apt install uidmap iproute2
[ "$(</proc/sys/kernel/unprivileged_userns_clone)" = "0" ] && echo "You must have unprivileged user namespaces enabled"

# install from source
cargo install --path .

# install from crates.io
cargo install socksns
```

#### Usage:

You must have a SOCKS proxy (for example Tor) running on port 9050.

```bash
socksns curl --proxy socks5h://localhost:9050 google.com
socksns torsocks curl google.com
```

[crates.io]: https://crates.io/crates/socksns
[Latest Version]: https://img.shields.io/crates/v/socksns.svg
