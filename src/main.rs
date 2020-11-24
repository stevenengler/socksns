use std::io::BufRead;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

use log::*;

// extension for UnixStream to pass file descriptors
use passfd::FdPassingExt;

type GenericResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

fn main() -> GenericResult<()> {
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    args.remove(0);

    if args.len() == 0 {
        println!("No program provided. Exiting.");
        return Ok(());
    }

    // initialize a basic logger
    let env = env_logger::Env::default().default_filter_or("info");
    let start = std::time::Instant::now();
    env_logger::Builder::from_env(env)
        .format(move |buf, rec| {
            let t = start.elapsed().as_secs_f32();
            writeln!(buf, "{:8.03} [{:5}] {}", t, rec.level(), rec.args())
        })
        .init();

    let (mut stream_parent, stream_child) = std::os::unix::net::UnixStream::pair()?;

    // let's fork before we do anything else since rust likes using mutexes
    let pid = unsafe { nix::unistd::fork() };

    // TODO: is there a nice way to close the opposite ends of the unix sockets here?
    let child_pid = match pid? {
        nix::unistd::ForkResult::Child => {
            run_child_proc(stream_child)?;
            std::process::exit(0);
        }
        nix::unistd::ForkResult::Parent { child: x, .. } => x,
    };

    // since the `unshare` library uses execve, we need to try to mimic the lookup
    // TODO: modify unshare/src/child.rs to use execvp instead of execve
    args[0] = find_exec(&args[0]);

    debug!("Found program: {:?}", args[0]);

    let user = users::get_user_by_uid(users::get_current_uid()).ok_or("User not found")?;

    let username = user.name().to_string_lossy().into_owned();
    let userid = user.uid();
    let groupid = user.primary_group_id();

    debug!("User info: uid={}, gid={}", userid, groupid);

    let subuids = get_sub_ids(&username, "/etc/subuid")?;
    let subgids = get_sub_ids(&username, "/etc/subgid")?;

    debug!("User maps: subuids={:?}, subgids={:?}", subuids, subgids);

    let uid_maps = vec![
        unshare::UidMap {
            inside_uid: 0,
            outside_uid: subuids.start,
            count: 1,
        },
        unshare::UidMap {
            inside_uid: userid,
            outside_uid: userid,
            count: 1,
        },
    ];

    let gid_maps = vec![
        unshare::GidMap {
            inside_gid: 0,
            outside_gid: subgids.start,
            count: 1,
        },
        unshare::GidMap {
            inside_gid: groupid,
            outside_gid: groupid,
            count: 1,
        },
    ];

    let mut namespace_cmd = unshare::Command::new(&args[0]);
    namespace_cmd.args(&args[1..]);
    namespace_cmd.unshare(&[unshare::Namespace::Net, unshare::Namespace::User]);
    namespace_cmd.set_id_map_commands("/usr/bin/newuidmap", "/usr/bin/newgidmap");
    namespace_cmd.set_id_maps(uid_maps, gid_maps);

    // TODO: is this useful? it seems to break bash
    //namespace_cmd.make_group_leader(true);

    let (sender, receiver) = std::sync::mpsc::channel();

    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let notify2 = notify.clone();

    // do a lot of stuff before we start the user's application
    // TODO: why doesn't before_unfreeze() take an FnOnce instead of an FnMut?!
    namespace_cmd.before_unfreeze(move |pid| {
        //set_id_map("/usr/bin/newuidmap", pid, userid, &subuids)?;
        //set_id_map("/usr/bin/newgidmap", pid, groupid, &subgids)?;

        // send the pid to the forked process
        let pid_u32: u32 = pid;
        stream_parent.write(&pid_u32.to_ne_bytes())?;

        // receive the socket bound in the new network namespace
        let listening_fd = stream_parent.recv_fd()?;

        debug!("Received listening fd: {}", listening_fd);

        // wait for child process to exit
        loop {
            match nix::sys::wait::wait()? {
                nix::sys::wait::WaitStatus::Exited(pid, rv) => {
                    if pid == child_pid {
                        if rv != 0 {
                            warn!("Forked process exited with status {}", rv);
                        }
                        break;
                    }
                }
                _ => {}
            }
        }

        let user_ns = open_namespace(pid, "user")?;
        let net_ns = open_namespace(pid, "net")?;

        // loop needed due to a race condition
        loop {
            // we don't actually want to run a program in this namespace,
            // we're just abusing the library
            let mut interface_cmd = unshare::Command::new("/bin/true");

            // need to perform this as root inside the user namespace
            interface_cmd.uid(0);
            interface_cmd.gid(0);

            // TODO: these options require a specific order, but the unshare lib uses a hashmap so
            // there is a race condition
            interface_cmd.set_namespace(&user_ns, unshare::Namespace::User)?;
            interface_cmd.set_namespace(&net_ns, unshare::Namespace::Net)?;

            // bring up the loopback interface in the new network namespace
            interface_cmd.before_exec(|| {
                // must be careful here: we can't allocate memory, use mutexes, etc
                bring_up_interface(b"lo")
            });

            match interface_cmd.status() {
                Err(x) => match x {
                    // unshare probably tried to join the net ns before the user ns
                    unshare::Error::SetNs(_) => {
                        continue;
                    }
                    x => Err(x)?,
                },
                Ok(x) => match x {
                    unshare::ExitStatus::Exited(0) => {}
                    unshare::ExitStatus::Exited(x) => warn!(
                        "Error while bringing up the loopback interface: status {:?}",
                        x
                    ),
                    unshare::ExitStatus::Signaled(x, _) => warn!(
                        "Error while bringing up the loopback interface: signal {:?}",
                        x
                    ),
                },
            }

            break;
        }

        // we can now start the proxy runtime
        sender.send(listening_fd)?;

        Ok(())
    });

    debug!(
        "Starting program: {}",
        namespace_cmd.display(&unshare::Style::short().path(true))
    );

    let mut proc_child = match namespace_cmd.spawn() {
        Err(unshare::Error::Fork(1)) => {
            warn!("Permission error when attempting to clone() new process");
            warn!("You may not have permission to create new user namespaces");
            Err(unshare::Error::Fork(1))
        }
        x => x,
    }?;

    let listening_fd = receiver.recv()?;

    let proxy_runtime_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        debug!("Starting proxy runtime");

        rt.block_on(run_proxy(listening_fd, notify2)).unwrap();
    });

    let rv = match proc_child.wait()? {
        unshare::ExitStatus::Exited(x) => x as i32,
        unshare::ExitStatus::Signaled(x, _) => 128 + (x as i32),
    };

    debug!("Program exited with status {}", rv);

    // the program has exited, so tell the proxy to stop listening for new connections
    notify.notify_one();

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

/// Read sub ids from a file (ex: /etc/subuid) for a given user.
fn get_sub_ids(username: &str, filename: &str) -> GenericResult<std::ops::Range<u32>> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(filename)?;

    let line = std::io::BufReader::new(f)
        .lines()
        // TODO: can make this nicer once `try_find()` is supported:
        // https://github.com/rust-lang/rust/issues/63178
        .map(|l| l.unwrap())
        .find(|l| l.trim().starts_with(&username))
        .ok_or(format!("Username {} not found in {}", username, filename))?;

    // line should look something like "username:subid_start:subid_count"
    let mut line = line.split(':').map(|x| x.trim());

    // we searched the file for the username, so this shouldn't fail
    assert!(line.next().unwrap() == username);

    let start: u32 = line.next().ok_or("No uid start")?.parse()?;
    let count: u32 = line.next().ok_or("No uid count")?.parse()?;

    Ok(start..(start + count))
}

/// Open the namespace for a given process.
fn open_namespace(pid: u32, ns_name: &str) -> Result<std::fs::File, std::io::Error> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(format!("/proc/{}/ns/{}", pid, ns_name))
}

/// Try to mimic the behaviour of `execve()` when choosing what executable binary to run.
fn find_exec(name: &std::ffi::OsStr) -> std::ffi::OsString {
    // if it has a '/' character, always treat it as a path
    if name.as_bytes().contains(&b'/') {
        std::env::current_dir().unwrap().join(name).into_os_string()
    } else {
        std::env::var_os("PATH")
            .and_then(|paths| {
                std::env::split_paths(&paths)
                    .filter_map(|dir| {
                        let full_path = dir.join(&name);
                        if full_path.is_file() {
                            let mode = full_path.metadata().unwrap().permissions().mode();
                            if mode & 0o111 != 0 {
                                Some(full_path)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .next()
            })
            .map_or(name.into(), |p| p.into_os_string())
    }
}

/// The helper process, which moves itself to the new network/user namespaces, and binds a socket.
fn run_child_proc(mut stream: std::os::unix::net::UnixStream) -> GenericResult<()> {
    let mut inbuf = [0u8; 4];
    stream.read(&mut inbuf)?;

    let pid: u32 = u32::from_ne_bytes(inbuf);

    let user_ns = open_namespace(pid, "user")?;
    let net_ns = open_namespace(pid, "net")?;

    let user_fd = user_ns.as_raw_fd();
    let net_fd = net_ns.as_raw_fd();

    nix::sched::setns(user_fd, nix::sched::CloneFlags::CLONE_NEWUSER)?;
    nix::sched::setns(net_fd, nix::sched::CloneFlags::CLONE_NEWNET)?;

    let listener = std::net::TcpListener::bind("127.0.0.1:9050")?;
    let fd = listener.into_raw_fd();

    stream.send_fd(fd)?;

    Ok(())
}

/// Run the proxy listener.
async fn run_proxy(
    listening_fd: i32,
    stop_notify: std::sync::Arc<tokio::sync::Notify>,
) -> GenericResult<()> {
    let listener = unsafe { std::net::TcpListener::from_raw_fd(listening_fd) };
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();

    loop {
        tokio::select! {
            _ = stop_notify.notified() => {
                debug!("Stopping listener");
                break Ok(());
            },
            res = listener.accept() => {
                let (socket, addr) = res.unwrap();
                debug!("New connection from {}", addr);
                tokio::spawn(async move {
                    if let Err(err) = proxy(socket).await {
                        warn!("Unexpected error from connection {}: {}", addr, err);
                    } else {
                        debug!("Closed connection from {}", addr);
                    }
                });
            },
        };
    }
}

/// Proxy data between the incoming connection and a new connection outside the network namespace.
async fn proxy(client: tokio::net::TcpStream) -> GenericResult<()> {
    let dst: std::net::SocketAddr = "127.0.0.1:9050".parse()?;

    let server = tokio::net::TcpStream::connect(dst).await?;

    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut server_r, mut server_w) = tokio::io::split(server);

    let to_server = tokio::io::copy(&mut client_r, &mut server_w);
    let to_client = tokio::io::copy(&mut server_r, &mut client_w);

    // proxy the data
    tokio::select! {
        res = to_server => res?,
        res = to_client => res?,
    };

    Ok(())
}
