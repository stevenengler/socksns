use std::io::Write;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;

use clap::Parser;

// extension for UnixStream to pass file descriptors
use passfd::FdPassingExt;

fn main() -> anyhow::Result<()> {
    let options = SocksnsOptions::parse();

    // initialize a basic logger
    let default_level = if options.debug { "debug" } else { "info" };
    let env = env_logger::Env::default().default_filter_or(default_level);
    let start = std::time::Instant::now();
    env_logger::Builder::from_env(env)
        .format(move |buf, rec| {
            let t = start.elapsed().as_secs_f32();
            writeln!(buf, "{:8.03} [{:5}] {}", t, rec.level(), rec.args())
        })
        .init();

    let (stream_parent, stream_child) = std::os::unix::net::UnixStream::pair()?;

    // set a timeout so that if the child process exits early, the parent process won't block
    stream_parent.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;

    let userid = nix::unistd::getuid();
    let groupid = nix::unistd::getgid();

    log::debug!("User info: uid={}, gid={}", userid, groupid);

    let options_copy = options.clone();

    let mut cmd = std::process::Command::new(&options.command[0]);
    cmd.args(&options.command[1..]);

    unsafe {
        cmd.pre_exec(move || {
            // warning: this code allocates memory and runs after the fork(), so there must
            // not be any threads running when this code starts (when the child spawns)

            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).unwrap();
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();

            // writes to a file in /proc/self
            fn write_to_file(fname: &str, bytes: &[u8]) -> std::io::Result<()> {
                let path = format!("/proc/self/{}", fname);
                let mut f = std::fs::OpenOptions::new()
                    .read(false)
                    .write(true)
                    .open(path)?;

                let num = f.write(bytes)?;
                assert!(num == bytes.len());
                Ok(())
            }

            // gain root privileges in the new user namespace
            write_to_file("setgroups", b"deny")?;
            write_to_file("uid_map", format!("0 {} 1", userid).as_bytes())?;
            write_to_file("gid_map", format!("0 {} 1", groupid).as_bytes())?;

            // bring up the loopback interface while we have root privileges
            bring_up_interface(b"lo")?;

            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).unwrap();

            // become the original user again
            write_to_file("uid_map", format!("{} 0 1", userid).as_bytes())?;
            write_to_file("gid_map", format!("{} 0 1", groupid).as_bytes())?;

            // rust sockets are automatically CLOEXEC
            let listener = std::net::TcpListener::bind((
                std::net::Ipv4Addr::LOCALHOST,
                options_copy.proxy.local_port,
            ))?;
            let fd = listener.into_raw_fd();

            // send the bound socket to the process outside of the namespace
            stream_child.send_fd(fd)?;

            Ok(())
        })
    };

    log::debug!("Starting program: {:?}", cmd);

    // warning: no threads can be running when spawn() is called
    let child = cmd.spawn();

    // check that the program was found
    if let Err(ref e) = child {
        if e.kind() == std::io::ErrorKind::NotFound {
            log::error!("Program {:?} cannot be found", options.command[0]);
            std::process::exit(1);
        }
    }

    let mut child = child?;

    // receive the socket bound inside the namespace
    let listening_fd = stream_parent.recv_fd();

    // check that the read didn't time out
    if let Err(ref e) = listening_fd {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            log::debug!("Didn't receive the fd on the socket");
            log::debug!("Assuming the child process crashed, so exiting...");
            std::process::exit(1);
        }
    }

    let listening_fd = listening_fd?;

    log::debug!("Received listening fd: {}", listening_fd);

    // used to stop the proxy server
    let stop_notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let stop_notify_clone = stop_notify.clone();

    let proxy_runtime_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        log::debug!("Starting proxy runtime");

        rt.block_on(run_proxy_server(listening_fd, stop_notify_clone, &options))
            .unwrap();
    });

    let exit_status = child.wait()?;
    let rv = match exit_status.code() {
        Some(code) => code as i32,
        // if it exited by a signal, set the exit code as bash does
        None => 128 + (exit_status.signal().unwrap() as i32),
    };

    log::debug!("Program exited with status: {}", rv);

    // the program has exited, so tell the proxy to stop listening for new connections
    stop_notify.notify_one();

    log::debug!("Waiting for proxy runtime to finish");

    // wait for existing proxy connections to finish
    proxy_runtime_thread.join().unwrap();

    std::process::exit(rv);
}

/// Convert a `&[u8]` to `&[i8]`. Useful when making C syscalls.
fn u8_to_i8_slice(s: &[u8]) -> &[i8] {
    unsafe { std::slice::from_raw_parts(s.as_ptr() as *const i8, s.len()) }
}

/// Bring up a given network interface.
fn bring_up_interface(interface_name: &[u8]) -> std::io::Result<()> {
    // must be careful here: we can't allocate memory, use mutexes, etc

    #[derive(Copy, Clone)]
    #[repr(C)]
    struct ifmap {
        mem_start: libc::c_ulong,
        mem_end: libc::c_ulong,
        base_addr: libc::c_ushort,
        irq: libc::c_uchar,
        dma: libc::c_uchar,
        port: libc::c_uchar,
    }

    #[repr(C)]
    union ifreq_union {
        ifr_addr: libc::sockaddr,
        ifr_dstaddr: libc::sockaddr,
        ifr_broadaddr: libc::sockaddr,
        ifr_netmask: libc::sockaddr,
        ifr_hwaddr: libc::sockaddr,
        ifr_flags: libc::c_short,
        ifr_ifindex: libc::c_int,
        ifr_metric: libc::c_int,
        ifr_mtu: libc::c_int,
        ifr_map: ifmap,
        ifr_slave: [libc::c_char; libc::IFNAMSIZ],
        ifr_newname: [libc::c_char; libc::IFNAMSIZ],
        ifr_data: *const libc::c_char,
    }

    #[repr(C)]
    struct ifreq {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        u: ifreq_union,
    }

    // following the steps at https://stackoverflow.com/a/17997505

    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if s < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut ifr: ifreq = unsafe { std::mem::zeroed() };

    // copy name, leaving room for a nul byte
    assert!(interface_name.len() < std::mem::size_of_val(&ifr.ifr_name));
    ifr.ifr_name[..interface_name.len()].clone_from_slice(u8_to_i8_slice(interface_name));

    unsafe { ifr.u.ifr_flags |= libc::IFF_UP as i16 };

    let rv = unsafe { libc::ioctl(s, libc::SIOCSIFFLAGS, &ifr as *const _) };
    if rv != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Run the proxy listener.
async fn run_proxy_server(
    listening_fd: i32,
    stop_notify: std::sync::Arc<tokio::sync::Notify>,
    options: &SocksnsOptions,
) -> anyhow::Result<()> {
    let listener = unsafe { std::net::TcpListener::from_raw_fd(listening_fd) };
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();

    loop {
        tokio::select! {
            // poll from top to bottom
            biased;
            _ = stop_notify.notified() => {
                log::debug!("Stopping listener");
                break Ok(());
            },
            res = listener.accept() => {
                let (socket, addr) = res.unwrap();
                log::debug!("New connection from {}", addr);
                let dst = (options.proxy.external_addr, options.proxy.external_port);
                tokio::spawn(async move {
                    if let Err(err) = proxy_connection(socket, dst.into()).await {
                        log::warn!("Unexpected error from connection {}: {}", addr, err);
                    } else {
                        log::debug!("Closed connection from {}", addr);
                    }
                });
            },
        };
    }
}

/// Proxy data between the incoming connection and a new connection outside the network namespace.
async fn proxy_connection(
    mut client: tokio::net::TcpStream,
    dst: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let mut server = tokio::net::TcpStream::connect(dst).await?;

    tokio::io::copy_bidirectional(&mut client, &mut server).await?;
    Ok(())
}

/// This tool will run a program in an isolated network namespace, allowing the program to connect
/// only to a single TCP address such as a SOCKS proxy
#[derive(Parser, Debug, Clone)]
#[clap(trailing_var_arg = true)]
struct SocksnsOptions {
    /// Show debug-level log messages.
    #[clap(long)]
    debug: bool,
    /// Proxy TCP connections made to 'localhost:LOCAL_PORT' within the new namespace to
    /// 'EXT_ADDRESS:EXT_PORT' outside of the namespace
    #[clap(long, value_name = "LOCAL_PORT:EXT_ADDRESS:EXT_PORT")]
    #[clap(default_value = "9050:localhost:9050")]
    proxy: ProxyOption,
    /// The command to run within the namespace
    #[clap(required = true)]
    command: Vec<std::ffi::OsString>,
}

#[derive(Parser, Debug, Copy, Clone)]
struct ProxyOption {
    local_port: u16,
    external_addr: std::net::IpAddr,
    external_port: u16,
}

impl std::str::FromStr for ProxyOption {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut x = s.split(':');

        let local_port = x.next().ok_or("Missing local port")?;
        let external_addr = x.next().ok_or("Missing external address")?;
        let external_port = x.next().ok_or("Missing external port")?;

        fn format_err(e: impl std::fmt::Display, val: impl std::fmt::Display) -> String {
            format!("{}: '{}'", e, val)
        }

        let local_port = local_port.parse().map_err(|e| format_err(e, local_port))?;

        let external_addr = match external_addr {
            "localhost" => std::net::Ipv6Addr::LOCALHOST.into(),
            x => x.parse().map_err(|e| format_err(e, external_addr))?,
        };

        let external_port = external_port
            .parse()
            .map_err(|e| format_err(e, external_port))?;

        Ok(Self {
            local_port,
            external_addr,
            external_port,
        })
    }
}
