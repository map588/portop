mod app;
mod port_scanner;
mod tui;
mod ui;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "portmaster", about = "TUI for managing open ports and processes")]
struct Args {
    /// Refresh interval in seconds
    #[arg(short, long, default_value = "2")]
    interval: u64,

    /// Filter by protocol (tcp, udp, all)
    #[arg(short, long, default_value = "all")]
    protocol: String,
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    let mut app = app::App::new(args.interval, &args.protocol);
    let terminal = tui::init()?;
    let result = app::run(terminal, &mut app);
    tui::restore()?;
    result
}
