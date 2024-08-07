# socksns

[![Latest Version]][crates.io]

This tool will run a program in an isolated network namespace, allowing the program to connect only to a single TCP address such as a SOCKS proxy. This can help prevent accidental proxy-bypass issues that could leak non-proxied requests.

#### Installation

Support for unprivileged user namespaces is required to run socksns. This is enabled by default in the mainline kernel and most distributions, but you may want to make sure that `/proc/sys/kernel/unprivileged_userns_clone` is not `0`.

```bash
# install the latest release from crates.io
cargo install socksns

# install the latest development version
git clone https://github.com/stevenengler/socksns.git
cargo install --path socksns
```

#### Example

If you have a SOCKS proxy (for example Tor) running on port 9050:

```bash
socksns torsocks curl google.com
socksns curl --proxy socks5h://localhost:9050 google.com
```

You can also proxy connections from other network namespaces:

```bash
podman run --rm -it --name socksns-demo --network none fedora:40
```

```bash
PID="$(podman ps -l --filter "name=socksns-demo" --format "{{.Pid}}")"
socksns --netns /proc/"$PID"/ns/net sleep infinity
```

Anything that's run in the podman container will be able to access the port
opened by socksns. This is useful when you want an isolated container which can
only access the Internet through a SOCKS proxy.

#### Usage

```
This tool will run a program in an isolated network namespace, allowing
the program to connect only to a single TCP address such as a SOCKS proxy

Usage: socksns [OPTIONS] <COMMAND>...

Arguments:
  <COMMAND>...
          The command to run within the namespace

Options:
      --debug
          Show debug-level log messages

      --proxy <LOCAL_PORT:EXT_ADDRESS:EXT_PORT>
          Configure how connections are proxied.

          Proxy TCP connections made to '127.0.0.1:LOCAL_PORT' within the
          new namespace to 'EXT_ADDRESS:EXT_PORT' outside of the
          namespace.

          [default: 9050:localhost:9050]

      --netns <PATH>
          Use an existing network namespace instead of creating a new
          isolated one.

          The program will be able to use all network interfaces within
          this namespace, possibly using them to access the Internet
          directly. If you wish to isolate the program's network traffic,
          you must configure the network namespace correctly. This option
          will also automatically enter the network namespace's user
          namespace. Elevated privileges may be required depending on how
          the user namespaces are structured.

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

[crates.io]: https://crates.io/crates/socksns
[Latest Version]: https://img.shields.io/crates/v/socksns.svg
