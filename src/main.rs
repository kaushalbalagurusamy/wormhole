use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use wormhole::{daemon, hookcmd, hub, install, mcp};

#[derive(Parser)]
#[command(
    name = "wormhole",
    version,
    about = "Live coordination between coding-agent sessions on different machines"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the hub. Listens on loopback unless --listen names the private-network address.
    Hub {
        #[arg(long, default_value = "127.0.0.1:7420")]
        listen: SocketAddr,
        #[arg(long, default_value = "wormhole-hub.sqlite")]
        db: PathBuf,
        /// `tailscale` (default) or `static` (loopback only; for tests and one machine).
        #[arg(long, default_value = "tailscale")]
        identity: String,
        #[arg(long, default_value = "tailscale")]
        tailscale_bin: PathBuf,
        /// DNS name clients use for the hub, such as its tailnet name. Repeatable.
        #[arg(long)]
        hostname: Vec<String>,
        /// Accept only this user (Tailscale login name, or tag:name for tagged nodes). Repeatable.
        #[arg(long)]
        allow: Vec<String>,
        /// TLS certificate chain (PEM), e.g. from `tailscale cert`. Serves wss:// and https://.
        /// Reloaded on SIGHUP.
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// TLS private key (PEM).
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
    },
    /// Run the per-machine daemon.
    Daemon {
        /// Hub WebSocket URL: wss://hub.example.ts.net:7420/ws with TLS, or ws:// to a loopback,
        /// Tailscale or *.ts.net address.
        #[arg(long)]
        hub: String,
        #[arg(long, default_value = "127.0.0.1:7421")]
        http: SocketAddr,
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Claim `user@machine`; only accepted by a hub running with --identity static.
        #[arg(long)]
        static_identity: Option<String>,
        /// Repo-relative glob where a conflicting edit is denied instead of warned. Repeatable.
        #[arg(long)]
        protected: Vec<String>,
        #[arg(long, default_value_t = 600)]
        lease_ttl_secs: u64,
        /// Extra CA certificate (PEM) to trust for a wss:// hub, for a private CA. The
        /// certificate is always verified. Repeatable.
        #[arg(long)]
        tls_ca: Vec<PathBuf>,
        /// Delegation policy (JSON): who may hand this machine's sessions tasks, and how much
        /// each may do. Without it the daemon never receives delegated tasks.
        #[arg(long)]
        delegation_policy: Option<PathBuf>,
    },
    /// The delegation kill switch.
    Delegation {
        #[command(subcommand)]
        cmd: DelegationCmd,
    },
    /// Stdio MCP server for one Claude Code session (tools and channel push).
    McpChannel {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Command hook (for SessionStart): hook JSON on stdin, output JSON on stdout.
    Hook {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Print the Claude Code settings and MCP config for a project. Writes nothing.
    Install {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long, default_value_t = 7421)]
        port: u16,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum DelegationCmd {
    /// Refuse every delegated task and close the open contracts until `resume`.
    Revoke {
        #[arg(long)]
        policy: PathBuf,
        /// Daemon socket, to close contracts at once instead of at their next check.
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Lift the kill switch.
    Resume {
        #[arg(long)]
        policy: PathBuf,
    },
}

fn default_socket() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".wormhole").join("daemon.sock")
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let r: Result<(), String> = match cli.cmd {
        Cmd::Hub {
            listen,
            db,
            identity,
            tailscale_bin,
            hostname,
            allow,
            tls_cert,
            tls_key,
        } => {
            let identity = match identity.as_str() {
                "tailscale" => hub::identity::IdentityConfig::Tailscale { bin: tailscale_bin },
                "static" => hub::identity::IdentityConfig::Static,
                other => {
                    eprintln!("unknown identity {other:?}; use tailscale or static");
                    std::process::exit(2);
                }
            };
            match hub::start(hub::HubConfig {
                listen,
                db,
                identity,
                hostnames: hostname,
                allow_users: allow,
                tls: tls_cert
                    .zip(tls_key)
                    .map(|(cert, key)| wormhole::tls::TlsFiles { cert, key }),
            })
            .await
            {
                Ok(h) => {
                    eprintln!("wormhole hub listening on {}", h.addr);
                    let _ = tokio::signal::ctrl_c().await;
                    h.shutdown().await;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Cmd::Daemon {
            hub,
            http,
            socket,
            static_identity,
            protected,
            lease_ttl_secs,
            tls_ca,
            delegation_policy,
        } => {
            let mut c = daemon::DaemonConfig::new(hub, socket.unwrap_or_else(default_socket));
            c.http_listen = http;
            c.static_identity = static_identity;
            c.protected = protected;
            c.lease_ttl = Duration::from_secs(lease_ttl_secs);
            c.extra_roots = tls_ca;
            c.delegation_policy = delegation_policy;
            match daemon::start(c).await {
                Ok(d) => {
                    eprintln!(
                        "wormhole daemon: hooks on http://{}/hook, socket {}",
                        d.http_addr,
                        d.socket_path.display()
                    );
                    let _ = tokio::signal::ctrl_c().await;
                    d.shutdown().await;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Cmd::Delegation {
            cmd: DelegationCmd::Revoke { policy, socket },
        } => match wormhole::delegation::revoke(&policy) {
            Err(e) => Err(e),
            Ok(()) => {
                eprintln!("wormhole: kill switch set; delegated tasks are refused until `wormhole delegation resume`");
                // Best effort: without it the daemon closes contracts at its next check.
                let socket = socket.unwrap_or_else(default_socket);
                let closed = match wormhole::local::LocalClient::connect(&socket).await {
                    Ok(mut c) => c.call("revoke", serde_json::json!({})).await.is_ok(),
                    Err(_) => false,
                };
                if !closed {
                    eprintln!("wormhole: the daemon was not told; it will close open contracts when it next checks");
                }
                Ok(())
            }
        },
        Cmd::Delegation {
            cmd: DelegationCmd::Resume { policy },
        } => wormhole::delegation::resume(&policy),
        Cmd::McpChannel { socket } => mcp::serve(socket.unwrap_or_else(default_socket)).await,
        Cmd::Hook { socket } => {
            let mut input = String::new();
            let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input);
            let input = serde_json::from_str(&input).unwrap_or(serde_json::Value::Null);
            let out = hookcmd::run(
                &socket.unwrap_or_else(default_socket),
                input,
                // Longer than the daemon's 800 ms hub deadline, so a slow hub is reported as such.
                Duration::from_millis(1500),
            )
            .await;
            println!("{out}");
            Ok(())
        }
        Cmd::Install {
            project,
            port,
            socket,
        } => {
            let exe = std::env::current_exe().map_err(|e| e.to_string());
            match exe {
                Ok(exe) => {
                    let project = std::fs::canonicalize(&project).unwrap_or(project);
                    let socket = socket.unwrap_or_else(default_socket);
                    // The printed config runs from the project directory, so the path must be absolute.
                    let socket = std::path::absolute(&socket).unwrap_or(socket);
                    match daemon::read_hook_token(&socket) {
                        Ok(Some(token)) => {
                            print!("{}", install::render(&project, &exe, port, &socket, &token));
                            Ok(())
                        }
                        Ok(None) => Err(format!(
                            "no hook token next to {}; start `wormhole daemon` once first",
                            socket.display()
                        )),
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(e),
            }
        }
    };
    if let Err(e) = r {
        eprintln!("wormhole: {e}");
        std::process::exit(1);
    }
}
