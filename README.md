# socksns

[![Latest Version]][crates.io]

This tool will run a program in an isolated network namespace, allowing the program to connect only to a single TCP address such as a SOCKS proxy. This can help prevent accidental proxy-bypass issues that could leak non-proxied requests.

#### Installation:

Support for unprivileged user namespaces is required to run socksns. This is enabled by default in the mainline kernel and most distributions, but you may want to make sure that `/proc/sys/kernel/unprivileged_userns_clone` is not `0`.

```bash
# install from source
git clone https://github.com/stevenengler/socksns.git
cd socksns && cargo install --path .

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
