use anyhow::{Context, Result, anyhow, bail};
use crossterm::execute;
use crossterm::terminal::{
    self, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use russh::ChannelMsg;
use russh::client::{self, Config, Handle, Handler};
use russh::keys::{HashAlg, PublicKeyOrCertificate, known_hosts};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::error::Error as StdError;
use std::fmt;
use std::future::{Future, pending};
use std::io::{self, IsTerminal, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

use crate::discovery::OpenTarget;
static SETUP_PIDFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

const SSH_PORT: u16 = 22;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub status: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelReason {
    User,
    TerminalLost,
    Signal,
}

#[derive(Debug)]
pub struct CommandCancelled(pub CancelReason);

impl fmt::Display for CommandCancelled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.0 {
            CancelReason::User => "installation cancelled by user",
            CancelReason::TerminalLost => "terminal closed during installation",
            CancelReason::Signal => "installation interrupted by process signal",
        };
        formatter.write_str(message)
    }
}

impl StdError for CommandCancelled {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SudoMode {
    Passwordless,
    PasswordRequired,
}

pub struct SshSession {
    client: Handle<HostKeyHandler>,
    sudo_mode: Option<SudoMode>,
}

struct HostKeyHandler {
    host: String,
}

impl Handler for HostKeyHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let public_key = server_public_key.public_key();
        let recorded = known_hosts::known_host_keys(&self.host, SSH_PORT)
            .with_context(|| format!("could not read known SSH host keys for {}", self.host))?;

        if recorded.iter().any(|(_, key)| key == &public_key) {
            return Ok(true);
        }
        if let Some((line, _)) = recorded.first() {
            bail!(
                "SSH host key for {} changed (known_hosts line {line}); refusing connection",
                self.host
            );
        }

        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        if !prompt_to_trust_host(&self.host, &fingerprint)? {
            return Ok(false);
        }

        known_hosts::learn_known_hosts(&self.host, SSH_PORT, &public_key)
            .with_context(|| format!("could not save SSH host key for {}", self.host))?;
        Ok(true)
    }
}

pub async fn connect(
    target: &OpenTarget,
    username: &str,
    password: &SecretString,
) -> Result<SshSession> {
    let host = target.address.to_string();
    let address = SocketAddr::new(IpAddr::V4(target.address), SSH_PORT);
    let config = Arc::new(Config::default());
    let handler = HostKeyHandler { host: host.clone() };
    let mut client = client::connect(config, address, handler)
        .await
        .with_context(|| format!("could not establish a trusted SSH connection to {host}"))?;

    let auth = client
        .authenticate_password(username, password.expose_secret().to_owned())
        .await
        .with_context(|| format!("SSH password authentication failed for {host}"))?;
    if !auth.success() {
        return Err(anyhow!(
            "SSH password authentication was rejected by {host}"
        ));
    }

    Ok(SshSession {
        client,
        sudo_mode: None,
    })
}

impl SshSession {
    pub async fn exec(&mut self, command: &str, stdin: Option<&[u8]>) -> Result<CommandOutput> {
        self.exec_stream(command, stdin, |_, _| {}).await
    }

    pub async fn exec_stream<F: FnMut(&[u8], bool)>(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
        on_output: F,
    ) -> Result<CommandOutput> {
        self.exec_stream_cancellable(command, stdin, on_output, pending::<CancelReason>())
            .await
    }

    pub async fn exec_stream_cancellable<F, C>(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
        mut on_output: F,
        cancel: C,
    ) -> Result<CommandOutput>
    where
        F: FnMut(&[u8], bool),
        C: Future<Output = CancelReason>,
    {
        let channel = self
            .client
            .channel_open_session()
            .await
            .context("could not open SSH command channel")?;
        channel
            .exec(true, command)
            .await
            .context("could not start remote SSH command")?;

        if let Some(input) = stdin.filter(|input| !input.is_empty()) {
            channel
                .data(input)
                .await
                .context("could not send command input over SSH")?;
        }
        channel
            .eof()
            .await
            .context("could not close remote command input")?;
        collect_command_output(channel, command, &mut on_output, cancel).await
    }
    pub async fn close(self) -> Result<()> {
        self.client
            .disconnect(
                russh::Disconnect::ByApplication,
                "installer closing SSH session",
                "en",
            )
            .await
            .context("could not close SSH session")
    }

    pub async fn sudo_exec(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
        sudo_password: &SecretString,
    ) -> Result<CommandOutput> {
        self.sudo_exec_stream(command, stdin, sudo_password, |_, _| {})
            .await
    }

    pub async fn sudo_exec_stream<F: FnMut(&[u8], bool)>(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
        sudo_password: &SecretString,
        on_output: F,
    ) -> Result<CommandOutput> {
        self.sudo_exec_stream_cancellable(
            command,
            stdin,
            sudo_password,
            on_output,
            pending::<CancelReason>(),
        )
        .await
    }

    pub async fn sudo_exec_stream_cancellable<F, C>(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
        sudo_password: &SecretString,
        mut on_output: F,
        cancel: C,
    ) -> Result<CommandOutput>
    where
        F: FnMut(&[u8], bool),
        C: Future<Output = CancelReason>,
    {
        match self.sudo_mode().await? {
            SudoMode::Passwordless => {
                let wrapped = format!("sudo -n -- sh -c {}", shell_quote(command));
                self.exec_stream_cancellable(&wrapped, stdin, &mut on_output, cancel)
                    .await
            }
            SudoMode::PasswordRequired => {
                if sudo_password.expose_secret().contains('\n')
                    || sudo_password.expose_secret().contains('\r')
                {
                    bail!("sudo password must be a single line");
                }
                let wrapped = format!("sudo -k -S -p '' -- sh -c {}", shell_quote(command));
                let channel = self
                    .client
                    .channel_open_session()
                    .await
                    .context("could not open SSH command channel")?;
                channel
                    .exec(true, wrapped.as_str())
                    .await
                    .context("could not start remote sudo command")?;

                let mut password_line = sudo_password.expose_secret().as_bytes().to_vec();
                password_line.push(b'\n');
                let password_line = SecretBox::new(Box::new(password_line));
                channel
                    .data(password_line.expose_secret().as_slice())
                    .await
                    .context("could not send sudo authentication over SSH")?;
                if let Some(input) = stdin.filter(|input| !input.is_empty()) {
                    channel
                        .data(input)
                        .await
                        .context("could not send command input over SSH")?;
                }
                channel
                    .eof()
                    .await
                    .context("could not close remote command input")?;
                collect_command_output(channel, &wrapped, &mut on_output, cancel).await
            }
        }
    }

    pub async fn sudo_exec_setup_cancellable<F, C>(
        &mut self,
        command: &str,
        sudo_password: &SecretString,
        on_output: F,
        cancel: C,
    ) -> Result<CommandOutput>
    where
        F: FnMut(&[u8], bool),
        C: Future<Output = CancelReason>,
    {
        let pidfile = setup_pidfile_path();
        let supervised = supervise_setup_command(command, &pidfile);
        match self
            .sudo_exec_stream_cancellable(&supervised, None, sudo_password, on_output, cancel)
            .await
        {
            Err(error) if error.downcast_ref::<CommandCancelled>().is_some() => {
                let stop_command = stop_setup_command(&pidfile);
                match timeout(
                    Duration::from_secs(5),
                    self.sudo_exec(&stop_command, None, sudo_password),
                )
                .await
                {
                    Ok(Ok(output)) if output.status == 0 => Err(error),
                    Ok(Ok(output)) => Err(error.context(format!(
                        "remote setup cleanup returned status {}",
                        output.status
                    ))),
                    Ok(Err(stop_error)) => Err(error.context(format!(
                        "could not stop the remote setup process group: {stop_error:#}"
                    ))),
                    Err(_) => {
                        Err(error
                            .context("timed out trying to stop the remote setup process group"))
                    }
                }
            }
            result => result,
        }
    }
    async fn sudo_mode(&mut self) -> Result<SudoMode> {
        if let Some(mode) = self.sudo_mode {
            return Ok(mode);
        }
        let probe = self.exec("sudo -k -n true", None).await?;
        let mode = if probe.status == 0 {
            SudoMode::Passwordless
        } else {
            SudoMode::PasswordRequired
        };
        self.sudo_mode = Some(mode);
        Ok(mode)
    }
}

fn setup_pidfile_path() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = SETUP_PIDFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "/run/.dartsnut-installer-setup.{:x}-{:x}-{:x}.pid",
        std::process::id(),
        timestamp,
        sequence
    )
}

fn supervise_setup_command(command: &str, pidfile: &str) -> String {
    let quoted_pidfile = shell_quote(pidfile);
    let child_command = format!(
        r#"umask 077; printf '%s\n' "$$" > {quoted_pidfile}; exec sh -c {}"#,
        shell_quote(command)
    );
    format!(
        r#"umask 077; child=; cleanup() {{ status=$?; trap - EXIT INT TERM HUP; pgid=$child; if [ -r {quoted_pidfile} ]; then pgid=$(cat {quoted_pidfile}) || pgid=$child; fi; case "$pgid" in ''|*[!0-9]*) ;; *) kill -TERM "-$pgid" 2>/dev/null || kill -TERM "$pgid" 2>/dev/null || true; sleep 1; kill -KILL "-$pgid" 2>/dev/null || kill -KILL "$pgid" 2>/dev/null || true;; esac; if [ -n "$child" ]; then wait "$child" 2>/dev/null || true; fi; rm -f -- {quoted_pidfile}; exit "$status"; }}; trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM HUP; setsid --wait sh -c {} & child=$!; wait "$child"; exit "$?""#,
        shell_quote(&child_command)
    )
}

fn stop_setup_command(pidfile: &str) -> String {
    let pidfile = shell_quote(pidfile);
    format!(
        r#"if [ -r {pidfile} ]; then pgid=$(cat {pidfile}) || exit $?; case "$pgid" in ''|*[!0-9]*) echo 'invalid setup process-group id' >&2; exit 2;; esac; kill -TERM "-$pgid" 2>/dev/null || kill -TERM "$pgid" 2>/dev/null || true; sleep 1; kill -KILL "-$pgid" 2>/dev/null || kill -KILL "$pgid" 2>/dev/null || true; if kill -0 "-$pgid" 2>/dev/null || kill -0 "$pgid" 2>/dev/null; then echo 'setup process group is still running' >&2; exit 1; fi; rm -f -- {pidfile}; fi"#
    )
}

async fn collect_command_output<F, C>(
    mut channel: russh::Channel<client::Msg>,
    command: &str,
    on_output: &mut F,
    cancel: C,
) -> Result<CommandOutput>
where
    F: FnMut(&[u8], bool),
    C: Future<Output = CancelReason>,
{
    let mut output = CommandOutput {
        status: 0,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let mut exit_status = None;
    let mut cancel = Box::pin(cancel);
    let mut cancelled = None;

    loop {
        let message = tokio::select! {
            reason = &mut cancel => {
                cancelled = Some(reason);
                break;
            }
            message = channel.wait() => message,
        };
        let Some(message) = message else {
            break;
        };
        match message {
            ChannelMsg::Data { data } => {
                on_output(&data, false);
                output.stdout.extend_from_slice(&data);
            }
            ChannelMsg::ExtendedData { data, .. } => {
                on_output(&data, true);
                output.stderr.extend_from_slice(&data);
            }
            ChannelMsg::ExitStatus {
                exit_status: status,
            } => exit_status = Some(status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    if let Some(reason) = cancelled {
        stop_remote_command(&mut channel, reason, on_output).await;
        return Err(
            anyhow::Error::new(CommandCancelled(reason)).context("remote command cancelled")
        );
    }

    output.status = exit_status
        .ok_or_else(|| anyhow!("remote SSH command ended without an exit status: {command}"))?;
    Ok(output)
}

async fn stop_remote_command<F: FnMut(&[u8], bool)>(
    channel: &mut russh::Channel<client::Msg>,
    reason: CancelReason,
    on_output: &mut F,
) {
    let first_signal = match reason {
        CancelReason::User => russh::Sig::INT,
        CancelReason::TerminalLost | CancelReason::Signal => russh::Sig::TERM,
    };
    let _ = channel.signal(first_signal).await;
    if wait_for_command_stop(channel, Duration::from_secs(2), on_output).await {
        return;
    }

    let _ = channel.signal(russh::Sig::TERM).await;
    if wait_for_command_stop(channel, Duration::from_secs(1), on_output).await {
        return;
    }

    let _ = channel.signal(russh::Sig::KILL).await;
    if !wait_for_command_stop(channel, Duration::from_secs(1), on_output).await {
        let _ = channel.close().await;
    }
}

async fn wait_for_command_stop<F: FnMut(&[u8], bool)>(
    channel: &mut russh::Channel<client::Msg>,
    grace: Duration,
    on_output: &mut F,
) -> bool {
    timeout(grace, async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => on_output(&data, false),
                ChannelMsg::ExtendedData { data, .. } => on_output(&data, true),
                ChannelMsg::ExitStatus { .. } | ChannelMsg::Close => return true,
                _ => {}
            }
        }
        true
    })
    .await
    .unwrap_or(false)
}

pub fn shell_quote(value: &str) -> String {
    let quote_count = value.bytes().filter(|byte| *byte == b'\'').count();
    let mut quoted = String::with_capacity(value.len() + quote_count * 3 + 2);
    quoted.push('\'');
    for character in value.chars() {
        if character == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

fn prompt_to_trust_host(host: &str, fingerprint: &str) -> Result<bool> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("cannot trust unknown SSH host {host} without an interactive terminal");
    }

    let was_raw = terminal::is_raw_mode_enabled().context("could not inspect terminal mode")?;
    if was_raw {
        disable_raw_mode().context("could not prepare terminal for host-key confirmation")?;
    }

    let mut stdout = io::stdout();
    if was_raw {
        if let Err(error) = execute!(stdout, LeaveAlternateScreen) {
            return match enable_raw_mode() {
                Ok(()) => Err(error).context("could not show SSH host-key confirmation"),
                Err(restore_error) => Err(anyhow!(
                    "could not show SSH host-key confirmation ({error}); could not restore raw terminal mode ({restore_error})"
                )),
            };
        }
    }

    let answer = (|| -> Result<bool> {
        writeln!(stdout, "\nSSH host {host} has an unknown host key.")?;
        writeln!(stdout, "SHA-256 fingerprint: {fingerprint}")?;
        write!(stdout, "Trust this device? [y/N] ")?;
        stdout.flush()?;
        let mut response = String::new();
        io::stdin()
            .read_line(&mut response)
            .context("could not read host-key confirmation")?;
        Ok(matches!(response.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
    })();

    let restore_screen = if was_raw {
        execute!(stdout, EnterAlternateScreen)
            .context("could not restore alternate terminal screen")
    } else {
        Ok(())
    };
    let restore_raw = if was_raw {
        enable_raw_mode().context("could not restore raw terminal mode")
    } else {
        Ok(())
    };

    match (restore_screen, restore_raw) {
        (Ok(()), Ok(())) => answer,
        (Err(screen_error), Err(raw_error)) => Err(anyhow!(
            "could not restore alternate terminal screen ({screen_error}); could not restore raw terminal mode ({raw_error})"
        )),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_shell_quote_preserves_values_as_one_literal_argument() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("hello world; $HOME"), "'hello world; $HOME'");
        assert_eq!(shell_quote("it's a test"), "'it'\\''s a test'");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn setup_cancellation_terminates_the_entire_remote_process_group() {
        use std::process::{Command, Stdio};
        use std::thread;

        let directory = std::env::temp_dir().join(format!(
            "dartsnut-setup-cancel-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let pidfile = directory
            .join("process-group.pid")
            .to_string_lossy()
            .into_owned();
        let started = shell_quote(&directory.join("started").to_string_lossy());
        let stopped = shell_quote(&directory.join("stopped").to_string_lossy());
        let setup = format!(
            "printf started > {started}; trap 'printf stopped > {stopped}; exit 130' INT TERM; while :; do sleep 1; done"
        );
        let supervisor = supervise_setup_command(&setup, &pidfile);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(supervisor)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !directory.join("started").exists() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            directory.join("started").exists(),
            "setup command never started"
        );
        assert!(
            std::path::Path::new(&pidfile).exists(),
            "process-group marker missing"
        );

        let cleanup = Command::new("/bin/sh")
            .arg("-c")
            .arg(stop_setup_command(&pidfile))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(cleanup.success(), "remote process-group cleanup failed");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "setup supervisor did not exit"
            );
            thread::sleep(Duration::from_millis(20));
        };
        assert!(!status.success(), "cancelled setup must not report success");
        assert!(
            directory.join("stopped").exists(),
            "setup process group did not receive TERM"
        );
        assert!(
            !std::path::Path::new(&pidfile).exists(),
            "process-group marker was not cleaned"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
