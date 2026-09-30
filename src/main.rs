mod app;
mod discovery;
mod install;
mod ssh;
mod ui;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "dartsnut-rpi-installer",
    version,
    about = "Prepare a Dartsnut Raspberry Pi"
)]
pub struct Cli {
    #[arg(long, value_name = "ADDRESS_OR_HOSTNAME")]
    pub ip: Option<String>,
    #[arg(long, value_name = "USERNAME")]
    pub user: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    app::run_install(cli).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_rejects_password_and_accepts_only_target_and_user() {
        assert!(Cli::try_parse_from(["installer", "--password", "secret"]).is_err());
        let cli =
            Cli::try_parse_from(["installer", "--ip", "pi.local", "--user", "operator"]).unwrap();
        assert_eq!(cli.ip.as_deref(), Some("pi.local"));
        assert_eq!(cli.user.as_deref(), Some("operator"));
    }
}
