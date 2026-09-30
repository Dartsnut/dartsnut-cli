use anyhow::{Context, Result, bail};
use secrecy::SecretString;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

use crate::discovery::OpenTarget;
use crate::ssh::{self, CommandOutput, SshSession};
use crate::ui::Ui;

const REPOSITORY_DIR: &str = "/home/rpi/dartsnut_rpi";
const DEVICE_JSON: &str = "/home/rpi/dartsnut_rpi/device.json";
const DIRECT_REPOSITORY_URL: &str = "https://github.com/Dartsnut/dartsnut_rpi.git";
const PROXY_REPOSITORY_URL: &str =
    "https://gh-proxy.org/https://github.com/Dartsnut/dartsnut_rpi.git";
const SETUP_COMMAND: &str = "cd /home/rpi/dartsnut_rpi && sudo ./setup.sh";
const REBOOT_COMMAND: &str =
    "sudo sh -c 'nohup sh -c \"sleep 1; systemctl reboot\" >/dev/null 2>&1 &'";

/// User-visible labels for every actionable remote stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    SshAuthentication,
    RemoteClassification,
    DeviceBackup,
    GitInstallation,
    RepositoryClone,
    OriginReset,
    LsusbDetection,
    DeviceJsonInstall,
    Setup,
    Reboot,
}

impl Stage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SshAuthentication => "SSH authentication",
            Self::RemoteClassification => "remote classification",
            Self::DeviceBackup => "device backup",
            Self::GitInstallation => "git installation",
            Self::RepositoryClone => "repository clone",
            Self::OriginReset => "origin reset",
            Self::LsusbDetection => "lsusb detection",
            Self::DeviceJsonInstall => "device.json install",
            Self::Setup => "setup.sh",
            Self::Reboot => "reboot",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceModel {
    PixelBoard,
    PixelDart,
}

/// The hardware rule is intentionally the same simple rule as the target's
/// runtime: a successful lsusb listing containing PIXELDARTS means PixelDart;
/// every other successful listing means PixelBoard.
pub fn detect_model(lsusb_output: &[u8]) -> DeviceModel {
    if lsusb_output.split(|byte| *byte == b'\n').any(|line| {
        line.windows(b"PIXELDARTS".len())
            .any(|part| part.eq_ignore_ascii_case(b"PIXELDARTS"))
    }) {
        DeviceModel::PixelDart
    } else {
        DeviceModel::PixelBoard
    }
}

/// Return the exact UTF-8 configuration bytes requested by the target setup.
pub fn device_json(model: DeviceModel) -> &'static [u8] {
    match model {
        DeviceModel::PixelBoard => br#"{"name": "PixelBoard", "serial": "1234567890", "model": "PixelBoard", "brightness": "100", "volume": "100"}"#,
        DeviceModel::PixelDart => br#"{"name": "PixelDart", "serial": "1234567890", "model": "PixelDart", "brightness": "100", "volume": "100"}"#,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebootVerificationState {
    WaitingForClose,
    WaitingForOpen,
    Complete,
}

/// A nonzero request is never considered accepted, so callers cannot enter
/// verification (or accidentally retry a reboot) until the request returned 0.
pub fn reboot_state_after_request(status: u32) -> Option<RebootVerificationState> {
    (status == 0).then_some(RebootVerificationState::WaitingForClose)
}

#[derive(Debug)]
struct RecoveryBackup {
    path: String,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct SudoState {
    alternate_password: Option<SecretString>,
    prompted: bool,
}

impl SudoState {
    fn password<'a>(&'a self, ssh_password: &'a SecretString) -> &'a SecretString {
        self.alternate_password.as_ref().unwrap_or(ssh_password)
    }
}

/// Run the complete remote installation against one already-discovered target.
pub async fn install(
    target: &OpenTarget,
    username: &str,
    password: &SecretString,
    ui: &mut Ui,
) -> Result<()> {
    let mut session = connect_with_retry(target, username, password, ui).await?;
    let mut sudo = SudoState::default();

    let mode = classify_repository(target, username, password, &mut session, &mut sudo, ui).await?;

    let recovery_backup = match mode {
        RepositoryMode::Recovery => {
            capture_recovery_backup(target, username, password, &mut session, &mut sudo, ui).await?
        }
        RepositoryMode::Fresh => {
            prepare_fresh_repository(target, username, password, &mut session, &mut sudo, ui)
                .await?;
            None
        }
    };

    if let Some(backup) = recovery_backup.as_ref() {
        restore_recovery_device(
            target,
            username,
            password,
            &mut session,
            &mut sudo,
            backup,
            ui,
        )
        .await?;
    } else {
        install_detected_device(target, username, password, &mut session, &mut sudo, ui).await?;
    }

    sudo_stage(
        target,
        username,
        password,
        &mut session,
        &mut sudo,
        Stage::Setup,
        SETUP_COMMAND,
        None,
        status_zero,
        ui,
    )
    .await?;

    let reboot = sudo_stage(
        target,
        username,
        password,
        &mut session,
        &mut sudo,
        Stage::Reboot,
        REBOOT_COMMAND,
        None,
        status_zero,
        ui,
    )
    .await?;
    let Some(mut reboot_state) = reboot_state_after_request(reboot.status) else {
        bail!("reboot request did not succeed")
    };

    // The reboot may disconnect before SSH acknowledges a graceful close.
    let _ = session.close().await;
    loop {
        match verify_reboot(target, username, password, &mut reboot_state).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                let output = error_output(&error);
                if !ui.retry_verification(&output)? {
                    return Err(error.context("reboot verification aborted"));
                }
                // This loop only verifies.  `sudo_stage` above has already
                // accepted the one and only reboot request. Keep the current
                // close/open phase so authentication failures do not wait for
                // a second shutdown that already happened.
                if reboot_state == RebootVerificationState::WaitingForClose {
                    ui.notice(
                        "Retrying the port-22 shutdown check; no reboot request will be sent.",
                    );
                } else {
                    ui.notice("Retrying post-reboot port-22 verification; no reboot request will be sent.");
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositoryMode {
    Recovery,
    Fresh,
}

async fn classify_repository(
    target: &OpenTarget,
    username: &str,
    ssh_password: &SecretString,
    session: &mut SshSession,
    sudo: &mut SudoState,
    ui: &mut Ui,
) -> Result<RepositoryMode> {
    let command = format!("test -d {}", ssh::shell_quote(REPOSITORY_DIR));
    let output = sudo_stage(
        target,
        username,
        ssh_password,
        session,
        sudo,
        Stage::RemoteClassification,
        &command,
        None,
        status_zero_or_clean_one,
        ui,
    )
    .await?;
    match output.status {
        0 => Ok(RepositoryMode::Recovery),
        1 => Ok(RepositoryMode::Fresh),
        _ => unreachable!("status predicate accepted only 0 or clean 1"),
    }
}

async fn capture_recovery_backup(
    target: &OpenTarget,
    username: &str,
    ssh_password: &SecretString,
    session: &mut SshSession,
    sudo: &mut SudoState,
    ui: &mut Ui,
) -> Result<Option<RecoveryBackup>> {
    let file_test = format!("test -f {}", ssh::shell_quote(DEVICE_JSON));
    let file = sudo_stage(
        target,
        username,
        ssh_password,
        session,
        sudo,
        Stage::DeviceBackup,
        &file_test,
        None,
        status_zero_or_clean_one,
        ui,
    )
    .await?;
    if file.status == 1 {
        return Ok(None);
    }

    let original = sudo_stage(
        target,
        username,
        ssh_password,
        session,
        sudo,
        Stage::DeviceBackup,
        &format!("cat {}", ssh::shell_quote(DEVICE_JSON)),
        None,
        status_zero,
        ui,
    )
    .await?
    .stdout;

    loop {
        // mktemp creates the target-side path atomically and with restrictive
        // permissions under sudo.  The later install copies the exact source
        // bytes into this reservation, so a pre-existing path is never
        // overwritten.
        let reservation = sudo_stage(
            target,
            username,
            ssh_password,
            session,
            sudo,
            Stage::DeviceBackup,
            "mktemp -p /home/rpi .dartsnut-device.json.backup.XXXXXXXXXXXX",
            None,
            status_zero,
            ui,
        )
        .await?;
        let path = String::from_utf8_lossy(&reservation.stdout)
            .trim()
            .to_owned();
        if !path.starts_with("/home/rpi/.dartsnut-device.json.backup.")
            || path.contains('\n')
            || path.contains('\r')
        {
            let malformed = mismatch_output("mktemp returned an invalid recovery backup path");
            if !ui.retry(Stage::DeviceBackup.as_str(), &malformed)? {
                bail!("device backup path allocation aborted")
            }
            continue;
        }

        let copy_command = format!(
            "install -m 0600 {} {}",
            ssh::shell_quote(DEVICE_JSON),
            ssh::shell_quote(&path)
        );
        loop {
            sudo_stage(
                target,
                username,
                ssh_password,
                session,
                sudo,
                Stage::DeviceBackup,
                &copy_command,
                None,
                status_zero,
                ui,
            )
            .await?;

            let copied = sudo_stage(
                target,
                username,
                ssh_password,
                session,
                sudo,
                Stage::DeviceBackup,
                &format!("cat {}", ssh::shell_quote(&path)),
                None,
                status_zero,
                ui,
            )
            .await?;
            if copied.stdout == original {
                ui.notice(&format!("Recovery backup: {path}"));
                return Ok(Some(RecoveryBackup {
                    path,
                    bytes: original,
                }));
            }

            let mismatch = mismatch_output("recovery backup bytes did not match device.json");
            if !ui.retry(Stage::DeviceBackup.as_str(), &mismatch)? {
                bail!("device backup verification aborted")
            }
            // Retry the reservation owned by this installer.  It is never a
            // pre-existing user path because mktemp created it exclusively.
        }
    }
}

async fn restore_recovery_device(
    target: &OpenTarget,
    username: &str,
    ssh_password: &SecretString,
    session: &mut SshSession,
    sudo: &mut SudoState,
    backup: &RecoveryBackup,
    ui: &mut Ui,
) -> Result<()> {
    let install_command = format!(
        "install -m 0644 {} {}",
        ssh::shell_quote(&backup.path),
        ssh::shell_quote(DEVICE_JSON)
    );
    loop {
        sudo_stage(
            target,
            username,
            ssh_password,
            session,
            sudo,
            Stage::DeviceJsonInstall,
            &install_command,
            None,
            status_zero,
            ui,
        )
        .await?;
        let readback = sudo_stage(
            target,
            username,
            ssh_password,
            session,
            sudo,
            Stage::DeviceJsonInstall,
            &format!("cat {}", ssh::shell_quote(DEVICE_JSON)),
            None,
            status_zero,
            ui,
        )
        .await?;
        if readback.stdout == backup.bytes {
            return Ok(());
        }
        let mismatch =
            mismatch_output("restored device.json bytes did not match the recovery backup");
        if !ui.retry(Stage::DeviceJsonInstall.as_str(), &mismatch)? {
            bail!("device.json restore verification aborted")
        }
    }
}

async fn prepare_fresh_repository(
    target: &OpenTarget,
    username: &str,
    ssh_password: &SecretString,
    session: &mut SshSession,
    sudo: &mut SudoState,
    ui: &mut Ui,
) -> Result<()> {
    let git_check = exec_stage(
        target,
        username,
        ssh_password,
        session,
        Stage::GitInstallation,
        "command -v git",
        None,
        status_zero_or_clean_one,
        ui,
    )
    .await?;
    if git_check.status == 1 {
        sudo_stage(
            target,
            username,
            ssh_password,
            session,
            sudo,
            Stage::GitInstallation,
            "apt-get update",
            None,
            status_zero,
            ui,
        )
        .await?;
        sudo_stage(
            target,
            username,
            ssh_password,
            session,
            sudo,
            Stage::GitInstallation,
            "apt-get install -y git",
            None,
            status_zero,
            ui,
        )
        .await?;
        exec_stage(
            target,
            username,
            ssh_password,
            session,
            Stage::GitInstallation,
            "command -v git",
            None,
            status_zero,
            ui,
        )
        .await?;
    }

    // A failed ping deliberately selects the proxy URL, including a missing
    // ping binary.  Only transport errors are actionable here.
    let ping = exec_control(
        target,
        username,
        ssh_password,
        session,
        Stage::RepositoryClone,
        "ping -c 1 -W 2 github.com",
        None,
        ui,
    )
    .await?;
    let clone_url = if ping.status == 0 {
        DIRECT_REPOSITORY_URL
    } else {
        PROXY_REPOSITORY_URL
    };

    // Fresh classification means this path was not a directory.  A file or
    // another pre-existing object must be left for Git to report, never deleted
    // by the installer.
    let preexisting = remote_exists(
        target,
        username,
        ssh_password,
        session,
        sudo,
        Stage::RepositoryClone,
        REPOSITORY_DIR,
        ui,
    )
    .await?;
    let clone_command = format!(
        "git clone {} {}",
        ssh::shell_quote(clone_url),
        ssh::shell_quote(REPOSITORY_DIR)
    );
    loop {
        let result = sudo_command(
            target,
            username,
            ssh_password,
            session,
            sudo,
            Stage::RepositoryClone,
            &clone_command,
            None,
            ui,
        )
        .await?;
        if result.status == 0 {
            break;
        }
        if !ui.retry(Stage::RepositoryClone.as_str(), &result)? {
            bail!("repository clone aborted")
        }
        if !preexisting && !clone_destination_conflict(&result) {
            let now_exists = remote_exists(
                target,
                username,
                ssh_password,
                session,
                sudo,
                Stage::RepositoryClone,
                REPOSITORY_DIR,
                ui,
            )
            .await?;
            if now_exists {
                let cleanup = format!("rm -rf -- {}", ssh::shell_quote(REPOSITORY_DIR));
                sudo_stage(
                    target,
                    username,
                    ssh_password,
                    session,
                    sudo,
                    Stage::RepositoryClone,
                    &cleanup,
                    None,
                    status_zero,
                    ui,
                )
                .await?;
            }
        }
    }

    sudo_stage(
        target,
        username,
        ssh_password,
        session,
        sudo,
        Stage::OriginReset,
        &format!(
            "git -C {} remote set-url origin {}",
            ssh::shell_quote(REPOSITORY_DIR),
            ssh::shell_quote(DIRECT_REPOSITORY_URL)
        ),
        None,
        status_zero,
        ui,
    )
    .await?;
    Ok(())
}

async fn install_detected_device(
    target: &OpenTarget,
    username: &str,
    ssh_password: &SecretString,
    session: &mut SshSession,
    sudo: &mut SudoState,
    ui: &mut Ui,
) -> Result<()> {
    let lsusb = sudo_stage(
        target,
        username,
        ssh_password,
        session,
        sudo,
        Stage::LsusbDetection,
        "lsusb",
        None,
        status_zero,
        ui,
    )
    .await?;
    ui.log(&combined_output(&lsusb));

    let payload = device_json(detect_model(&lsusb.stdout));
    let install_command = format!(
        "install -m 0644 /dev/stdin {}",
        ssh::shell_quote(DEVICE_JSON)
    );
    loop {
        sudo_stage(
            target,
            username,
            ssh_password,
            session,
            sudo,
            Stage::DeviceJsonInstall,
            &install_command,
            Some(payload),
            status_zero,
            ui,
        )
        .await?;
        let readback = sudo_stage(
            target,
            username,
            ssh_password,
            session,
            sudo,
            Stage::DeviceJsonInstall,
            &format!("cat {}", ssh::shell_quote(DEVICE_JSON)),
            None,
            status_zero,
            ui,
        )
        .await?;
        if readback.stdout == payload {
            return Ok(());
        }
        let mismatch =
            mismatch_output("installed device.json bytes did not match the generated payload");
        if !ui.retry(Stage::DeviceJsonInstall.as_str(), &mismatch)? {
            bail!("device.json verification aborted")
        }
    }
}

async fn remote_exists(
    target: &OpenTarget,
    username: &str,
    ssh_password: &SecretString,
    session: &mut SshSession,
    sudo: &mut SudoState,
    stage: Stage,
    path: &str,
    ui: &mut Ui,
) -> Result<bool> {
    let quoted_path = ssh::shell_quote(path);
    let command = format!("test -e {quoted_path} || test -L {quoted_path}");
    let output = sudo_stage(
        target,
        username,
        ssh_password,
        session,
        sudo,
        stage,
        &command,
        None,
        status_zero_or_clean_one,
        ui,
    )
    .await?;
    Ok(output.status == 0)
}

async fn connect_with_retry(
    target: &OpenTarget,
    username: &str,
    password: &SecretString,
    ui: &mut Ui,
) -> Result<SshSession> {
    loop {
        match ssh::connect(target, username, password).await {
            Ok(session) => return Ok(session),
            Err(error) => {
                let output = error_output(&error);
                if !ui.retry(Stage::SshAuthentication.as_str(), &output)? {
                    return Err(error.context("SSH authentication aborted"));
                }
            }
        }
    }
}

async fn reconnect_with_retry(
    target: &OpenTarget,
    username: &str,
    password: &SecretString,
    ui: &mut Ui,
) -> Result<SshSession> {
    connect_with_retry(target, username, password, ui).await
}

async fn exec_control(
    target: &OpenTarget,
    username: &str,
    password: &SecretString,
    session: &mut SshSession,
    stage: Stage,
    command: &str,
    stdin: Option<&[u8]>,
    ui: &mut Ui,
) -> Result<CommandOutput> {
    loop {
        match session.exec(command, stdin).await {
            Ok(output) => return Ok(output),
            Err(error) => {
                let display = error_output(&error);
                if !ui.retry(stage.as_str(), &display)? {
                    return Err(error.context(format!("{stage} aborted")));
                }
                *session = reconnect_with_retry(target, username, password, ui).await?;
            }
        }
    }
}

async fn exec_stage(
    target: &OpenTarget,
    username: &str,
    password: &SecretString,
    session: &mut SshSession,
    stage: Stage,
    command: &str,
    stdin: Option<&[u8]>,
    accepted: fn(&CommandOutput) -> bool,
    ui: &mut Ui,
) -> Result<CommandOutput> {
    loop {
        let output = exec_control(
            target, username, password, session, stage, command, stdin, ui,
        )
        .await?;
        if accepted(&output) {
            return Ok(output);
        }
        if !ui.retry(stage.as_str(), &output)? {
            bail!("{stage} aborted")
        }
    }
}

async fn sudo_command(
    target: &OpenTarget,
    username: &str,
    ssh_password: &SecretString,
    session: &mut SshSession,
    sudo: &mut SudoState,
    stage: Stage,
    command: &str,
    stdin: Option<&[u8]>,
    ui: &mut Ui,
) -> Result<CommandOutput> {
    loop {
        let attempt = {
            let sudo_password = sudo.password(ssh_password);
            if stage == Stage::Setup {
                ui.setup_running()?;
                session
                    .sudo_exec_setup_cancellable(
                        command,
                        sudo_password,
                        |chunk, _stderr| ui.log(&String::from_utf8_lossy(chunk)),
                        crate::ui::wait_for_setup_cancel(),
                    )
                    .await
            } else {
                session.sudo_exec(command, stdin, sudo_password).await
            }
        };
        match attempt {
            Ok(output) => {
                if looks_like_sudo_rejection(&output) && !sudo.prompted {
                    let displayed = combined_output(&output);
                    if !displayed.is_empty() {
                        ui.log(&displayed);
                    }
                    ui.notice("The SSH password was rejected by sudo; enter the sudo password.");
                    sudo.alternate_password = Some(ui.password("Sudo password: ")?);
                    sudo.prompted = true;
                    continue;
                }
                return Ok(output);
            }
            Err(error) => {
                let displayed = error_output(&error);
                if error.downcast_ref::<ssh::CommandCancelled>().is_some() {
                    ui.notice(&format!("{error:#}"));
                    return Err(error);
                }
                if !ui.retry(stage.as_str(), &displayed)? {
                    return Err(error.context(format!("{stage} aborted")));
                }
                *session = reconnect_with_retry(target, username, ssh_password, ui).await?;
            }
        }
    }
}

async fn sudo_stage(
    target: &OpenTarget,
    username: &str,
    ssh_password: &SecretString,
    session: &mut SshSession,
    sudo: &mut SudoState,
    stage: Stage,
    command: &str,
    stdin: Option<&[u8]>,
    accepted: fn(&CommandOutput) -> bool,
    ui: &mut Ui,
) -> Result<CommandOutput> {
    loop {
        let output = sudo_command(
            target,
            username,
            ssh_password,
            session,
            sudo,
            stage,
            command,
            stdin,
            ui,
        )
        .await?;
        if accepted(&output) {
            return Ok(output);
        }
        if !ui.retry(stage.as_str(), &output)? {
            bail!("{stage} aborted")
        }
    }
}

fn status_zero(output: &CommandOutput) -> bool {
    output.status == 0
}

fn status_zero_or_clean_one(output: &CommandOutput) -> bool {
    output.status == 0 || (output.status == 1 && output.stderr.is_empty())
}

fn looks_like_sudo_rejection(output: &CommandOutput) -> bool {
    let text = combined_output(output).to_ascii_lowercase();
    [
        "sorry, try again",
        "incorrect password",
        "authentication failure",
        "a password is required",
        "a terminal is required",
        "no tty present",
        "must have a tty",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn clone_destination_conflict(output: &CommandOutput) -> bool {
    let text = combined_output(output).to_ascii_lowercase();
    text.contains("destination path") || (text.contains("already exists") && text.contains("clone"))
}

fn error_output(error: &anyhow::Error) -> CommandOutput {
    CommandOutput {
        status: 255,
        stdout: Vec::new(),
        stderr: format!("{error:#}").into_bytes(),
    }
}

fn mismatch_output(message: &str) -> CommandOutput {
    CommandOutput {
        status: 1,
        stdout: Vec::new(),
        stderr: message.as_bytes().to_vec(),
    }
}

fn combined_output(output: &CommandOutput) -> String {
    let mut bytes = Vec::with_capacity(output.stdout.len() + output.stderr.len() + 1);
    bytes.extend_from_slice(&output.stdout);
    if !output.stdout.is_empty() && !output.stderr.is_empty() && !output.stdout.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(&output.stderr);
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn verify_reboot(
    target: &OpenTarget,
    username: &str,
    password: &SecretString,
    state: &mut RebootVerificationState,
) -> Result<()> {
    wait_for_port_transition(
        target.address,
        22,
        state,
        Duration::from_secs(15),
        Duration::from_secs(180),
    )
    .await?;

    let mut fresh = ssh::connect(target, username, password)
        .await
        .context("authenticate after reboot")?;
    let authenticated = fresh
        .exec("true", None)
        .await
        .context("verify the post-reboot SSH session")?;
    if authenticated.status != 0 {
        let output = combined_output(&authenticated);
        bail!(
            "post-reboot authentication command returned status {}: {}",
            authenticated.status,
            output
        )
    }
    *state = RebootVerificationState::Complete;
    Ok(())
}

async fn wait_for_port_transition(
    address: Ipv4Addr,
    port: u16,
    state: &mut RebootVerificationState,
    close_limit: Duration,
    open_limit: Duration,
) -> Result<()> {
    if *state == RebootVerificationState::WaitingForClose {
        if !wait_for_closed(address, port, close_limit).await {
            bail!("port 22 did not close after the accepted reboot request")
        }
        *state = RebootVerificationState::WaitingForOpen;
    }
    if *state != RebootVerificationState::WaitingForOpen {
        bail!("invalid reboot verification state")
    }
    if !wait_for_open(address, port, open_limit).await {
        bail!("port 22 did not reopen after the accepted reboot request")
    }
    Ok(())
}

async fn wait_for_closed(address: Ipv4Addr, port: u16, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if !port_open(address, port).await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_for_open(address: Ipv4Addr, port: u16, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if port_open(address, port).await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_secs(1)).await;
    }
}

async fn port_open(address: Ipv4Addr, port: u16) -> bool {
    matches!(
        timeout(Duration::from_secs(1), TcpStream::connect((address, port))).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixeldarts_marker_is_case_insensitive_per_line() {
        assert_eq!(
            detect_model(b"Bus 001 PIXELDARTS controller\n"),
            DeviceModel::PixelDart
        );
        assert_eq!(
            detect_model(b"Bus 001 pixeldarts controller\n"),
            DeviceModel::PixelDart
        );
        assert_eq!(
            detect_model(b"Bus 001 PixelBoard controller\n"),
            DeviceModel::PixelBoard
        );
    }

    #[test]
    fn generated_json_has_exact_requested_bytes() {
        assert_eq!(
            device_json(DeviceModel::PixelBoard),
            br#"{"name": "PixelBoard", "serial": "1234567890", "model": "PixelBoard", "brightness": "100", "volume": "100"}"#
        );
        assert_eq!(
            device_json(DeviceModel::PixelDart),
            br#"{"name": "PixelDart", "serial": "1234567890", "model": "PixelDart", "brightness": "100", "volume": "100"}"#
        );
    }

    #[test]
    fn nonzero_reboot_request_never_enters_verification() {
        assert_eq!(
            reboot_state_after_request(1),
            None,
            "a failed request cannot schedule verification or a second reboot"
        );
        assert_eq!(
            reboot_state_after_request(0),
            Some(RebootVerificationState::WaitingForClose)
        );
    }

    #[test]
    fn remote_classification_accepts_only_clean_status_one() {
        let mut result = CommandOutput {
            status: 1,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert!(status_zero_or_clean_one(&result));
        result.stderr.extend_from_slice(b"permission denied");
        assert!(!status_zero_or_clean_one(&result));
        result.status = 2;
        result.stderr.clear();
        assert!(!status_zero_or_clean_one(&result));
    }
    #[tokio::test]
    async fn reboot_retry_waits_for_reopen_without_a_second_shutdown() {
        let _loopback_lock = crate::LOOPBACK_LISTENER_TEST_LOCK.lock().await;
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut state = reboot_state_after_request(0).unwrap();
        assert!(
            wait_for_port_transition(
                Ipv4Addr::LOCALHOST,
                port,
                &mut state,
                Duration::from_millis(50),
                Duration::from_millis(50),
            )
            .await
            .is_err()
        );
        assert_eq!(state, RebootVerificationState::WaitingForOpen);

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        wait_for_port_transition(
            Ipv4Addr::LOCALHOST,
            port,
            &mut state,
            Duration::from_millis(50),
            Duration::from_millis(50),
        )
        .await
        .unwrap();
        assert_eq!(state, RebootVerificationState::WaitingForOpen);
        drop(listener);
    }
}
