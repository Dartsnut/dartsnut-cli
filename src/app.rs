use anyhow::{Context, Result};
use secrecy::SecretString;

use crate::{
    Cli,
    discovery::{build_scan_targets, scan_port22_progress},
    install,
    ui::{ScanAction, Ui},
};

/// Run the complete host-side interactive flow.
///
/// Discovery is deliberately performed before any credential prompt.  The
/// `Ui` owns raw mode and the alternate screen from this point until every
/// error, abort, or successful installation returns.
pub async fn run_install(cli: Cli) -> Result<()> {
    let mut ui = Ui::new().context("initialize installer terminal")?;
    let mut requested_ip = cli.ip.clone();

    let (target, username, password) = loop {
        let mut scope = scan_scope(requested_ip.as_deref());
        let targets = match build_scan_targets(requested_ip.as_deref()).await {
            Ok(targets) => targets,
            Err(error) => {
                ui.notice(&format!("Discovery failed: {error:#}"));
                match ui.no_targets(&scope)? {
                    ScanAction::Retry => continue,
                    ScanAction::EnterTarget => {
                        requested_ip = Some(ui.target_input()?);
                        continue;
                    }
                    ScanAction::Quit => return Ok(()),
                }
            }
        };

        let mut progress_error = None;
        let open_targets = scan_port22_progress(targets, |done, total, current, open| {
            if progress_error.is_none() {
                progress_error = ui.scan_progress(done, total, current, open).err();
            }
        })
        .await;
        if let Some(error) = progress_error {
            return Err(error).context("render port-22 scan progress");
        }

        if open_targets.is_empty() && requested_ip.is_some() {
            scope.push_str(" (closed)");
        }

        // This is the final list screen.  Nothing below this call asks for a
        // username or password until all scan attempts have completed.
        ui.scan_complete(&open_targets, &scope)?;
        if open_targets.is_empty() {
            match ui.no_targets(&scope)? {
                ScanAction::Retry => continue,
                ScanAction::EnterTarget => {
                    requested_ip = Some(ui.target_input()?);
                    continue;
                }
                ScanAction::Quit => return Ok(()),
            }
        }

        let use_default = ui.default_login()?;
        let (username, password) = if use_default {
            (
                String::from("rpi"),
                SecretString::new(String::from("rpi").into()),
            )
        } else {
            let username = ui.username(cli.user.as_deref())?;
            let password = ui.password("Password: ")?;
            (username, password)
        };
        let target = ui.select_target(&open_targets)?;
        break (target, username, password);
    };

    install::install(&target, &username, &password, &mut ui).await?;
    ui.notice("Installation completed successfully. Press any key to exit.");
    ui.wait_for_key()?;
    Ok(())
}

fn scan_scope(requested_ip: Option<&str>) -> String {
    requested_ip
        .map(|value| format!("explicit target {value}"))
        .unwrap_or_else(|| {
            String::from(
                "non-loopback IPv4 /24 interfaces plus dartsnut.local and raspberrypi.local",
            )
        })
}
