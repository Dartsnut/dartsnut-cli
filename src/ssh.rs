use anyhow::{Context, Result, anyhow, bail};
use crossterm::execute;
use crossterm::terminal::{
    self, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use russh::ChannelMsg;
use russh::client::{self, Config, Handle, Handler};
use russh::keys::{HashAlg, PublicKeyOrCertificate, known_hosts};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::io::{self, IsTerminal, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::discovery::OpenTarget;

const SSH_PORT: u16 = 22;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub status: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

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
        mut on_output: F,
    ) -> Result<CommandOutput> {
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
        collect_command_output(channel, command, &mut on_output).await
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
        mut on_output: F,
    ) -> Result<CommandOutput> {
        match self.sudo_mode().await? {
            SudoMode::Passwordless => {
                let wrapped = format!("sudo -n -- sh -c {}", shell_quote(command));
                self.exec_stream(&wrapped, stdin, &mut on_output).await
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
                collect_command_output(channel, &wrapped, &mut on_output).await
            }
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

async fn collect_command_output<F: FnMut(&[u8], bool)>(
    mut channel: russh::Channel<client::Msg>,
    command: &str,
    on_output: &mut F,
) -> Result<CommandOutput> {
    let mut output = CommandOutput {
        status: 0,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let mut exit_status = None;
    while let Some(message) = channel.wait().await {
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

    output.status = exit_status
        .ok_or_else(|| anyhow!("remote SSH command ended without an exit status: {command}"))?;
    Ok(output)
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
    use super::shell_quote;

    #[test]
    fn posix_shell_quote_preserves_values_as_one_literal_argument() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("hello world; $HOME"), "'hello world; $HOME'");
        assert_eq!(shell_quote("it's a test"), "'it'\\''s a test'");
    }
}
