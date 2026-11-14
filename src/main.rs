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
    },
    /// Run the per-machine daemon.
    Daemon {
        /// Hub WebSocket URL, e.g. ws://100.64.0.1:7420/ws
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
        } => {
            let mut c = daemon::DaemonConfig::new(hub, socket.unwrap_or_else(default_socket));
            c.http_listen = http;
            c.static_identity = static_identity;
            c.protected = protected;
            c.lease_ttl = Duration::from_secs(lease_ttl_secs);
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
        Cmd::McpChannel { socket } => mcp::serve(socket.unwrap_or_else(default_socket)).await,
        Cmd::Hook { socket } => {
            let mut input = String::new();
            let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input);
            let input = serde_json::from_str(&input).unwrap_or(serde_json::Value::Null);
            let out = hookcmd::run(
                &socket.unwrap_or_else(default_socket),
                input,
                Duration::from_millis(800),
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
