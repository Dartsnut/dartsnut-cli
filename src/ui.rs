use anyhow::{Context, Result, bail};
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures_util::StreamExt;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use secrecy::SecretString;
use std::io::{self, Stdout};
use zeroize::Zeroizing;

use crate::{
    discovery::{OpenTarget, ScanTarget},
    ssh::{CancelReason, CommandOutput},
};

/// The action selected on the scan result screen when no SSH service was found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanAction {
    Retry,
    EnterTarget,
    Quit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UiPhase {
    Initial,
    Scanning,
    Results,
    NoTargets,
    Credentials,
    Installing,
}

impl UiPhase {
    fn credentials_allowed(self) -> bool {
        matches!(self, Self::Results)
    }

    fn input_allowed(self) -> bool {
        matches!(self, Self::Credentials | Self::Installing)
    }
}

/// Owns the terminal for the complete installer lifetime.
///
/// Creating a `Ui` enters the alternate screen and raw mode.  Its `Drop`
/// implementation is intentionally best-effort so that all error paths leave
/// the user's terminal usable, including errors returned from an SSH stage.
pub struct Ui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    phase: UiPhase,
    spinner: usize,
    logs: Vec<String>,
    results: Vec<OpenTarget>,
    scope: String,
}

impl Ui {
    /// Enter the interactive terminal.  This is the cleanup guard required by
    /// the application: callers should create it before discovery or SSH.
    pub fn new() -> Result<Self> {
        enable_raw_mode().context("enable terminal raw mode")?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, Hide) {
            let _ = disable_raw_mode();
            return Err(error).context("enter terminal alternate screen");
        }

        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(error) => {
                let mut stdout = io::stdout();
                let _ = execute!(stdout, LeaveAlternateScreen, Show);
                let _ = disable_raw_mode();
                return Err(error).context("create terminal backend");
            }
        };

        Ok(Self {
            terminal,
            phase: UiPhase::Initial,
            spinner: 0,
            logs: Vec::new(),
            results: Vec::new(),
            scope: String::new(),
        })
    }

    pub fn setup_running(&mut self) -> Result<()> {
        let message = "Running setup.sh. Press Esc, q, or Ctrl+C to cancel; cancellation may leave partial changes.";
        self.logs.push(message.to_owned());
        self.draw("Installer", vec![Line::from(message)], None)
    }

    /// Render one completed port-22 scan attempt.
    pub fn scan_progress(
        &mut self,
        completed: usize,
        total: usize,
        current: &ScanTarget,
        open_count: usize,
    ) -> Result<()> {
        self.phase = UiPhase::Scanning;
        let spinner = ["|", "/", "-", "\\"][self.spinner % 4];
        self.spinner = self.spinner.wrapping_add(1);
        self.draw(
            "Scanning",
            vec![
                Line::from(format!(
                    "Scanning port 22: {completed}/{total} ({})",
                    current.address
                )),
                Line::from(format!("{spinner} Current target: {}", current.label())),
                Line::from(format!("Open SSH targets found: {open_count}")),
            ],
            None,
        )
    }

    /// Render the final open-target list.  This method never reads input, so
    /// callers can guarantee that credentials are requested only afterwards.
    pub fn scan_complete(&mut self, targets: &[OpenTarget], scope: &str) -> Result<()> {
        self.phase = UiPhase::Results;
        self.results = targets.to_vec();
        self.scope = scope.to_owned();
        let mut lines = vec![Line::from(format!("Scan scope: {scope}")), Line::from("")];
        if targets.is_empty() {
            lines.push(Line::from("No open SSH targets."));
        } else {
            lines.extend(open_target_lines(targets));
        }
        self.draw("Open SSH targets", lines, None)
    }

    /// Show the exact three actions available when discovery found nothing.
    pub fn no_targets(&mut self, scope: &str) -> Result<ScanAction> {
        self.phase = UiPhase::NoTargets;
        self.draw(
            "No SSH targets found",
            vec![
                Line::from(format!("Scan scope: {scope}")),
                Line::from(""),
                Line::from("Retry scan"),
                Line::from("Enter an IP/hostname"),
                Line::from("Quit"),
                Line::from(""),
                Line::from("Choose [r] Retry scan, [e] Enter an IP/hostname, or [q] Quit"),
            ],
            None,
        )?;
        loop {
            match self.read_key()?.code {
                KeyCode::Char('r' | 'R') | KeyCode::Enter => return Ok(ScanAction::Retry),
                KeyCode::Char('e' | 'E') => return Ok(ScanAction::EnterTarget),
                KeyCode::Char('q' | 'Q') | KeyCode::Esc => return Ok(ScanAction::Quit),
                _ => {}
            }
        }
    }

    pub fn default_login(&mut self) -> Result<bool> {
        if !self.phase.credentials_allowed() {
            bail!("credentials requested before the final SSH target list");
        }
        let mut lines = vec![
            Line::from(format!("Scan scope: {}", self.scope)),
            Line::from(""),
        ];
        lines.extend(open_target_lines(&self.results));
        lines.push(Line::from(""));
        lines.push(Line::from("Use default Raspberry Pi login rpi:rpi? [Y/n]"));
        self.draw("Credentials", lines, None)?;
        let use_default = self.read_yes_no(true)?;
        self.phase = UiPhase::Credentials;
        Ok(use_default)
    }

    /// Ask for an explicit target after a failed/empty scan.
    pub fn target_input(&mut self) -> Result<String> {
        self.read_text("Enter an IP/hostname", "Target: ", None, false, true)
    }

    /// Read a username, optionally prefilled from `--user`.
    pub fn username(&mut self, default: Option<&str>) -> Result<String> {
        if !self.phase.input_allowed() {
            bail!("username requested before the credential screen");
        }
        self.read_text("Credentials", "Username: ", default, false, true)
    }

    /// Read a password without ever rendering its bytes.
    pub fn password(&mut self, prompt: &str) -> Result<SecretString> {
        if !self.phase.input_allowed() {
            bail!("password requested before the credential screen");
        }
        let value = self.read_text("Credentials", prompt, None, true, false)?;
        Ok(SecretString::new(value.into()))
    }

    /// Select one target after credentials have been collected.  A sole target
    /// is selected without a second prompt.
    pub fn select_target(&mut self, targets: &[OpenTarget]) -> Result<OpenTarget> {
        if !self.phase.input_allowed() {
            bail!("target selected before credentials");
        }
        let target = if let [target] = targets {
            target.clone()
        } else {
            if targets.is_empty() {
                bail!("cannot select from an empty target list");
            }
            let mut lines = vec![Line::from("Select a target:")];
            lines.extend(open_target_lines(targets));
            let index = self.read_target_index(&lines, targets.len())?;
            targets[index].clone()
        };
        self.phase = UiPhase::Installing;
        Ok(target)
    }

    /// Append a non-secret message to the installer log and render it.
    pub fn log(&mut self, message: &str) {
        for line in message.lines() {
            self.logs.push(line.to_owned());
        }
        let _ = self.draw("Installer log", vec![Line::from(message.to_owned())], None);
    }

    /// Display a non-fatal notice without waiting for input.
    pub fn notice(&mut self, message: &str) {
        self.log(message);
    }

    /// Display the captured streams for a failed stage and ask whether to
    /// repeat that same stage.  Secrets are supplied separately by the SSH
    /// layer and therefore do not appear in this output.
    pub fn retry(&mut self, stage: &str, output: &CommandOutput) -> Result<bool> {
        self.retry_with_prompt(stage, output, "Retry this step? [Y/n]")
    }

    pub fn retry_verification(&mut self, output: &CommandOutput) -> Result<bool> {
        self.retry_with_prompt("reboot verification", output, "Retry verification [Y/n]")
    }

    fn retry_with_prompt(
        &mut self,
        stage: &str,
        output: &CommandOutput,
        prompt: &str,
    ) -> Result<bool> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut lines = vec![
            Line::from(format!("Stage failed: {stage}")),
            Line::from(format!("Exit status: {}", output.status)),
            Line::from(""),
            Line::from("stdout:"),
        ];
        append_multiline(&mut lines, &stdout);
        lines.push(Line::from("stderr:"));
        append_multiline(&mut lines, &stderr);
        lines.push(Line::from(""));
        lines.push(Line::from(prompt.to_owned()));
        self.draw("Installer stage failed", lines, None)?;
        self.read_yes_no(true)
    }

    /// Wait for a final acknowledgement before dropping the terminal guard.
    pub fn wait_for_key(&mut self) -> Result<()> {
        let _ = self.read_key()?;
        Ok(())
    }

    fn read_target_index(&mut self, base: &[Line<'static>], count: usize) -> Result<usize> {
        let mut value = String::new();
        loop {
            let mut lines = base.to_vec();
            lines.push(Line::from("Enter a target number:"));
            lines.push(Line::from(value.clone()));
            self.draw("Open SSH targets", lines, None)?;
            match self.read_key()?.code {
                KeyCode::Char(character) if character.is_ascii_digit() => {
                    if value.len() < 3 {
                        value.push(character);
                    }
                }
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Enter => {
                    if let Ok(number) = value.parse::<usize>() {
                        if (1..=count).contains(&number) {
                            return Ok(number - 1);
                        }
                    }
                    value.clear();
                }
                KeyCode::Esc => bail!("target selection cancelled"),
                _ => {}
            }
        }
    }

    fn read_text(
        &mut self,
        title: &str,
        prompt: &str,
        initial: Option<&str>,
        masked: bool,
        require_non_empty: bool,
    ) -> Result<String> {
        if initial.is_none()
            && !matches!(
                self.phase,
                UiPhase::NoTargets | UiPhase::Results | UiPhase::Credentials | UiPhase::Installing
            )
        {
            bail!("text input requested before an interactive screen");
        }
        let mut value = Zeroizing::new(initial.unwrap_or_default().to_owned());
        loop {
            let shown = display_input(&value, masked);
            self.draw(
                title,
                vec![Line::from(prompt.to_owned()), Line::from(shown)],
                None,
            )?;
            loop {
                let key = self.read_key()?;
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        bail!("cancelled by user")
                    }
                    KeyCode::Char(character) => value.push(character),
                    KeyCode::Backspace => {
                        value.pop();
                    }
                    KeyCode::Enter => break,
                    KeyCode::Esc => bail!("input cancelled"),
                    _ => {}
                }
                let shown = display_input(&value, masked);
                self.draw(
                    title,
                    vec![Line::from(prompt.to_owned()), Line::from(shown)],
                    None,
                )?;
            }
            if !require_non_empty || !value.trim().is_empty() {
                return Ok(std::mem::take(&mut *value));
            }
            self.notice("Username and target values cannot be empty.");
            value.clear();
        }
    }

    fn read_yes_no(&mut self, default_yes: bool) -> Result<bool> {
        loop {
            match self.read_key()?.code {
                KeyCode::Char('y' | 'Y') | KeyCode::Enter => return Ok(true),
                KeyCode::Char('n' | 'N') => return Ok(false),
                KeyCode::Esc => return Ok(!default_yes),
                _ => {}
            }
        }
    }

    fn read_key(&self) -> Result<KeyEvent> {
        loop {
            if let Event::Key(key) = event::read().context("read terminal input")? {
                return Ok(key);
            }
        }
    }

    fn draw<'a>(
        &mut self,
        title: &str,
        mut lines: Vec<Line<'a>>,
        footer: Option<&str>,
    ) -> Result<()> {
        if !self.logs.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Log",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            for message in self.logs.iter().rev().take(8).rev() {
                lines.push(Line::from(format!("  {message}")));
            }
        }
        let footer = footer.map(str::to_owned);
        self.terminal
            .draw(|frame| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Min(1),
                        Constraint::Length(if footer.is_some() { 3 } else { 1 }),
                    ])
                    .split(frame.area());
                let body = Paragraph::new(Text::from(lines))
                    .block(Block::default().borders(Borders::ALL).title(title))
                    .wrap(Wrap { trim: false });
                frame.render_widget(body, chunks[0]);
                if let Some(footer) = footer.as_deref() {
                    let footer = Paragraph::new(footer)
                        .style(Style::default().fg(Color::DarkGray))
                        .wrap(Wrap { trim: false });
                    frame.render_widget(footer, chunks[1]);
                }
            })
            .map(|_| ())
            .map_err(Into::into)
    }
}

pub async fn wait_for_setup_cancel() -> CancelReason {
    let mut events = EventStream::new();
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let Ok(mut hangup) = signal(SignalKind::hangup()) else {
            return CancelReason::Signal;
        };
        let Ok(mut terminate) = signal(SignalKind::terminate()) else {
            return CancelReason::Signal;
        };
        tokio::select! {
            reason = wait_for_cancel_key(&mut events) => reason,
            _ = &mut ctrl_c => CancelReason::Signal,
            _ = hangup.recv() => CancelReason::TerminalLost,
            _ = terminate.recv() => CancelReason::Signal,
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            reason = wait_for_cancel_key(&mut events) => reason,
            _ = &mut ctrl_c => CancelReason::Signal,
        }
    }
}

async fn wait_for_cancel_key(events: &mut EventStream) -> CancelReason {
    while let Some(event) = events.next().await {
        match event {
            Ok(Event::Key(key)) if is_cancel_key(key) => return CancelReason::User,
            Ok(_) => {}
            Err(_) => return CancelReason::TerminalLost,
        }
    }
    CancelReason::TerminalLost
}

fn is_cancel_key(key: KeyEvent) -> bool {
    matches!(key.code, KeyCode::Esc | KeyCode::Char('q' | 'Q'))
        || (matches!(key.code, KeyCode::Char('c' | 'C'))
            && key.modifiers.contains(KeyModifiers::CONTROL))
}
impl Drop for Ui {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen, Show);
        let _ = self.terminal.show_cursor();
    }
}

fn open_target_lines(targets: &[OpenTarget]) -> Vec<Line<'static>> {
    targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            let label = target
                .hostname
                .as_ref()
                .map(|host| format!("{} ({host})", target.address))
                .unwrap_or_else(|| target.address.to_string());
            Line::from(format!("{}. {label}", index + 1))
        })
        .collect()
}

fn append_multiline(lines: &mut Vec<Line<'static>>, text: &str) {
    if text.is_empty() {
        lines.push(Line::from(""));
        return;
    }
    for line in text.split('\n') {
        lines.push(Line::from(line.trim_end_matches('\r').to_owned()));
    }
}

fn display_input(value: &str, masked: bool) -> String {
    if masked {
        "*".repeat(value.chars().count())
    } else {
        value.to_owned()
    }
}
#[cfg(test)]
mod tests {
    use super::{UiPhase, is_cancel_key};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn credentials_are_gated_until_final_scan_results() {
        assert!(!UiPhase::Initial.credentials_allowed());
        assert!(!UiPhase::Scanning.credentials_allowed());
        assert!(!UiPhase::NoTargets.credentials_allowed());
        assert!(UiPhase::Results.credentials_allowed());
    }

    #[test]
    fn typed_credentials_are_only_available_after_default_prompt() {
        assert!(!UiPhase::Results.input_allowed());
        assert!(UiPhase::Credentials.input_allowed());
        assert!(UiPhase::Installing.input_allowed());
    }

    #[test]
    fn setup_cancellation_keys_are_distinct_from_normal_keys() {
        assert!(is_cancel_key(KeyEvent::new(
            KeyCode::Esc,
            KeyModifiers::NONE
        )));
        assert!(is_cancel_key(KeyEvent::new(
            KeyCode::Char('q'),
            KeyModifiers::NONE
        )));
        assert!(is_cancel_key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        )));
        assert!(!is_cancel_key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::NONE
        )));
        assert!(UiPhase::Installing.input_allowed());
    }
}
