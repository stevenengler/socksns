# socksns

[![Latest Version]][crates.io]

This tool will run a program in an isolated network namespace, allowing the program to connect only to a single TCP address such as a SOCKS proxy. This can help prevent accidental proxy-bypass issues that could leak non-proxied requests.

#### Installation

Support for unprivileged user namespaces is required to run socksns. This is enabled by default in the mainline kernel and most distributions, but you may want to make sure that `/proc/sys/kernel/unprivileged_userns_clone` is not `0`.

```bash
# install from source
git clone https://github.com/stevenengler/socksns.git
cd socksns && cargo install --path .

# install the latest release from crates.io
cargo install socksns
```

#### Example

If you have a SOCKS proxy (for example Tor) running on port 9050:

```bash
socksns torsocks curl google.com
socksns curl --proxy socks5h://localhost:9050 google.com
```

#### Usage

```
This tool will run a program in an isolated network namespace, allowing
the program to connect only to a single TCP address such as a SOCKS proxy

Usage: socksns [OPTIONS] <COMMAND>...

Arguments:
  <COMMAND>...  The command to run within the namespace

Options:
      --debug
          Show debug-level log messages
      --proxy <LOCAL_PORT:EXT_ADDRESS:EXT_PORT>
          Proxy TCP connections made to '127.0.0.1:LOCAL_PORT' within the
          new namespace to 'EXT_ADDRESS:EXT_PORT' outside of the namespace
          [default: 9050:localhost:9050]
  -h, --help
          Print help information
  -V, --version
          Print version information
```

[crates.io]: https://crates.io/crates/socksns
[Latest Version]: https://img.shields.io/crates/v/socksns.svg
