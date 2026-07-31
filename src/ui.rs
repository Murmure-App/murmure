//! The terminal interface.
//!
//! Owns the screen and the keyboard, and nothing else. The rest of the program
//! talks to it through two channels: it pushes lines in through a [`Screen`]
//! handle, and pulls typed lines out through an ordinary `mpsc`. That keeps
//! every other module free of drawing code, and means the whole program can be
//! driven by a pipe when there is no terminal.
//!
//! # Why arti's logs go to a file
//!
//! Anything written to stdout by something other than this module lands in the
//! middle of the frame and corrupts it. `main` points `tracing` at a file for
//! exactly that reason; `RUST_LOG=info` still works, the output just lives in
//! `.murmure/murmure.log` instead of on screen.

use std::collections::VecDeque;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event, EventStream, KeyCode, KeyEvent,
    KeyEventKind, KeyModifiers,
};
use futures::StreamExt as _;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use tokio::sync::mpsc;

/// How many lines of history are kept.
///
/// Bounded on purpose: a conversation that never ends must not grow until the
/// machine swaps. Old lines fall off the top, which is what a terminal does
/// anyway.
const SCROLLBACK: usize = 2_000;

/// Rows a PageUp/PageDown moves when the viewport height is not known yet.
///
/// It normally is — [`App::page`] uses the real height minus a row of overlap,
/// so a page turn keeps one line of context. This is only the value before the
/// first frame has been drawn.
const PAGE: usize = 10;

/// What kind of line this is, which decides how it is coloured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Program chatter: connection stages, call boundaries, command output.
    System,
    /// Something we said.
    Mine,
    /// Something they said.
    Theirs,
    /// A failure the operator has to see.
    Error,
}

/// One line of history.
///
/// Public for the same reason as [`Update`]: it is named by the channel type,
/// never constructed from outside.
#[derive(Debug, Clone)]
pub struct Entry {
    kind: Kind,
    text: String,
}

impl Entry {
    /// What this line says.
    ///
    /// Exists so a test can react to what the operator would react to, rather
    /// than to a timer: the conversation loop answers the keyboard before it
    /// answers the wire, so "type `/accept` once the offer is on screen" is the
    /// only sequencing that matches how the program is actually used.
    #[cfg(test)]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// What the rest of the program sends to the screen.
///
/// Public only because it names the channel [`channel`] hands back; nothing
/// outside this module constructs one, and [`Screen`] is the only way to send.
pub enum Update {
    /// Append a line.
    Line(Entry),
    /// Replace the status shown in the title bar.
    Status(String),
    /// Start or stop accepting typed lines.
    Accepting(bool),
    /// Put this on the system clipboard.
    Clipboard(String),
}

/// A handle for putting lines on screen from anywhere in the program.
///
/// Cloneable and cheap. Sending is synchronous and never blocks: the channel is
/// unbounded because the producer is a human typing or a peer on a 0,1 Mo/s
/// link, and dropping a line the operator needed would be worse than the
/// memory.
#[derive(Clone)]
pub struct Screen(mpsc::UnboundedSender<Update>);

impl Screen {
    /// Put a line on screen.
    pub fn say(&self, kind: Kind, text: impl Into<String>) {
        // A closed channel means the UI is gone, i.e. the program is exiting.
        let _ = self.0.send(Update::Line(Entry {
            kind,
            text: text.into(),
        }));
    }

    /// Program chatter.
    pub fn system(&self, text: impl Into<String>) {
        self.say(Kind::System, text);
    }

    /// A failure the operator has to see.
    pub fn error(&self, text: impl Into<String>) {
        self.say(Kind::Error, text);
    }

    /// Replace the status shown in the title bar.
    pub fn status(&self, text: impl Into<String>) {
        let _ = self.0.send(Update::Status(text.into()));
    }

    /// Start or stop accepting typed lines.
    ///
    /// Off until Tor is up. Accepting input that nothing is reading is worse
    /// than refusing it: the line queues invisibly and fires minutes later,
    /// against a program that has moved on.
    pub fn accepting(&self, yes: bool) {
        let _ = self.0.send(Update::Accepting(yes));
    }

    /// Put text on the system clipboard.
    ///
    /// Best effort: it goes through the terminal (see [`copy_to_clipboard`]),
    /// and a terminal that does not support it drops it silently. There is no
    /// reply to wait for, so nothing here can tell whether it worked.
    pub fn copy(&self, text: impl Into<String>) {
        let _ = self.0.send(Update::Clipboard(text.into()));
    }
}

/// Build a screen handle and the receiver [`run`] consumes.
pub fn channel() -> (Screen, mpsc::UnboundedReceiver<Update>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Screen(tx), rx)
}

/// Everything drawn, and where the view is.
struct App {
    /// Shown in the title bar, next to the address.
    status: String,
    /// Our own address, abbreviated. Always visible so it can be read out loud
    /// without leaving the conversation.
    title: String,
    /// Scrollback, oldest first.
    history: VecDeque<Entry>,
    /// What is being typed.
    input: String,
    /// Files dropped on the window, waiting to be sent.
    ///
    /// A terminal turns a drag-and-drop into a paste of the file's path, which
    /// is 60-odd characters of noise in a one-line input box. The path is kept
    /// here and shown as `[name]`, so what is on screen is what was dropped.
    attached: Vec<PathBuf>,
    /// Screen rows scrolled up from the bottom. Zero means following the tail.
    ///
    /// Rows, not entries. Counting entries is the obvious thing and it is
    /// wrong: with wrapping on, one entry is one to three rows — a 56-character
    /// address is two, a discovery key is two more — so one press of Up moved
    /// the view by an amount that depended on what happened to be there, and a
    /// page turn overshot by a whole screen.
    scroll_back: usize,
    /// The history box, as of the last frame: usable width, then height.
    ///
    /// Kept because wrapping is what turns entries into rows, so nothing can be
    /// clamped or paged without it. Seeded with a plausible terminal so the
    /// first keypress behaves even if it lands before the first draw.
    viewport: (usize, usize),
    /// Whether typed lines are accepted at all. False until Tor is up.
    accepting: bool,
}

impl App {
    fn new(title: String) -> Self {
        Self {
            status: "starting".to_owned(),
            title,
            history: VecDeque::new(),
            input: String::new(),
            attached: Vec::new(),
            scroll_back: 0,
            viewport: (80, PAGE),
            accepting: false,
        }
    }

    /// Every row the history occupies at the current width.
    fn total_rows(&self) -> usize {
        self.history
            .iter()
            .map(|e| rows_for(&e.text, self.viewport.0))
            .sum()
    }

    /// How far a page key moves: a screenful, less one row of overlap so the
    /// reader keeps a line they have already seen.
    fn page(&self) -> usize {
        self.viewport.1.saturating_sub(1).max(1)
    }

    /// Move the view: positive scrolls back into history, negative comes
    /// forward. Clamped at both ends, so holding a key never overshoots.
    fn scroll(&mut self, rows: isize) {
        // Scrolling stops when the oldest row reaches the top of the box, not
        // when it reaches the bottom — otherwise the view can be dragged into
        // empty space above the history.
        let limit = self.total_rows().saturating_sub(self.viewport.1);
        let moved = self.scroll_back as isize + rows;
        self.scroll_back = moved.clamp(0, limit as isize) as usize;
    }

    /// Take a paste: an existing file becomes an attachment, anything else is
    /// text.
    ///
    /// A drag-and-drop and a paste are the same event to a terminal, so they are
    /// told apart by what the text turns out to be. That is not a heuristic
    /// about how it looks — the path is resolved, and only a file that is
    /// actually there is treated as one.
    fn paste(&mut self, text: &str) {
        if let Some(path) = as_dropped_file(text) {
            self.attached.push(path);
            return;
        }
        // Newlines would submit several lines at once from a source that is not
        // the keyboard; a pasted paragraph becomes one line instead.
        for c in text.chars() {
            match c {
                '\n' | '\r' => self.input.push(' '),
                c if c.is_control() => {}
                c => self.input.push(c),
            }
        }
    }

    /// What the input box shows: the attachments, then what is being typed.
    fn input_display(&self) -> String {
        let mut shown = String::new();
        for path in &self.attached {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string_lossy().into_owned());
            shown.push_str(&format!("[{name}] "));
        }
        shown.push_str(&self.input);
        shown
    }

    /// The lines Enter should send: one `/send` per attachment, then the text.
    ///
    /// Emitting commands rather than a new event type keeps the interface's only
    /// output a line of text, exactly as if it had been typed — so the idle loop
    /// and the conversation need to know nothing about drag-and-drop.
    fn submit(&mut self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .attached
            .drain(..)
            .map(|p| format!("/send {}", p.display()))
            .collect();
        let text = std::mem::take(&mut self.input);
        if !text.trim().is_empty() {
            lines.push(text);
        }
        lines
    }

    fn push(&mut self, entry: Entry) {
        self.history.push_back(entry);
        while self.history.len() > SCROLLBACK {
            let Some(dropped) = self.history.pop_front() else {
                break;
            };
            // Keep the view anchored on the same text as lines fall off the
            // top: the offset is measured from the bottom, so it has to lose
            // exactly the rows that left.
            self.scroll_back = self
                .scroll_back
                .saturating_sub(rows_for(&dropped.text, self.viewport.0));
        }
    }
}

/// Run the interface until the operator quits or the terminal closes.
///
/// Typed lines go out through `typed`. Returns when the input channel is
/// closed by the caller, or on Ctrl-C.
pub async fn run(
    mut updates: mpsc::UnboundedReceiver<Update>,
    typed: mpsc::Sender<String>,
    title: String,
) -> Result<()> {
    // `ratatui::init` enters the alternate screen, turns on raw mode, and
    // installs a panic hook that restores the terminal. Without that hook a
    // panic leaves the operator with an unusable shell.
    let mut terminal = ratatui::init();
    // Bracketed paste makes the terminal deliver a paste — and a drag-and-drop,
    // which every terminal implements as a paste of the file's path — as one
    // event instead of a burst of keystrokes. Without it a dropped path arrives
    // character by character and there is nothing to recognise it by.
    let bracketed = crossterm::execute!(std::io::stdout(), EnableBracketedPaste).is_ok();

    let result = event_loop(&mut terminal, &mut updates, typed, title).await;

    if bracketed {
        // Leaving it on would make the shell after us receive pastes wrapped in
        // escape sequences it does not expect.
        let _ = crossterm::execute!(std::io::stdout(), DisableBracketedPaste);
    }
    ratatui::restore();
    result
}

async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    updates: &mut mpsc::UnboundedReceiver<Update>,
    typed: mpsc::Sender<String>,
    title: String,
) -> Result<()> {
    let mut app = App::new(title);
    let mut keys = EventStream::new();

    terminal.draw(|frame| draw(frame, &mut app)).context("drawing")?;

    loop {
        tokio::select! {
            update = updates.recv() => {
                match update {
                    Some(Update::Line(entry)) => app.push(entry),
                    Some(Update::Status(status)) => app.status = status,
                    Some(Update::Accepting(yes)) => app.accepting = yes,
                    Some(Update::Clipboard(text)) => copy_to_clipboard(&text),
                    // The program is shutting down.
                    None => return Ok(()),
                }
                // Drain whatever else is already queued before redrawing: a
                // burst of lines costs one frame, not one frame each.
                while let Ok(update) = updates.try_recv() {
                    match update {
                        Update::Line(entry) => app.push(entry),
                        Update::Status(status) => app.status = status,
                        Update::Accepting(yes) => app.accepting = yes,
                        Update::Clipboard(text) => copy_to_clipboard(&text),
                    }
                }
            }

            key = keys.next() => {
                match key {
                    Some(Ok(Event::Key(key))) => {
                        if handle_key(key, &mut app, &typed).await? {
                            return Ok(());
                        }
                    }
                    Some(Ok(Event::Paste(text))) => app.paste(&text),
                    // Resize and mouse events just need a redraw.
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e).context("reading a terminal event"),
                    None => return Ok(()),
                }
            }
        }

        terminal.draw(|frame| draw(frame, &mut app)).context("drawing")?;
    }
}

/// Handle one key. Returns `true` when the operator wants out.
async fn handle_key(key: KeyEvent, app: &mut App, typed: &mpsc::Sender<String>) -> Result<bool> {
    // Windows reports both press and release; acting on both doubles every key.
    if key.kind != KeyEventKind::Press {
        return Ok(false);
    }

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    // Ctrl-C always works: nobody should be trapped for forty seconds of
    // bootstrap with no way out.
    if key.code == KeyCode::Char('c') && ctrl {
        return Ok(true);
    }
    // Scrolling is harmless while starting up; typing is not, because nothing
    // is reading it yet.
    if !app.accepting && !matches!(key.code, KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown | KeyCode::End) {
        return Ok(false);
    }

    match key.code {
        KeyCode::Char('u') if ctrl => {
            app.input.clear();
            app.attached.clear();
        }
        // Scrolling, bound to keys every keyboard has. A MacBook has no
        // PageUp/PageDown/End except through Fn, so the arrows and the
        // less(1) conventions carry the feature; the named keys stay as
        // aliases for keyboards that have them.
        KeyCode::Char('b') if ctrl => app.scroll(app.page() as isize),
        KeyCode::Char('f') if ctrl => app.scroll(-(app.page() as isize)),
        KeyCode::Char('e') if ctrl => app.scroll_back = 0,
        KeyCode::Up => app.scroll(1),
        KeyCode::Down => app.scroll(-1),
        KeyCode::Char(c) => app.input.push(c),
        // Once the text is gone, Backspace takes attachments off the end, so a
        // file dropped by mistake is removed the way anything else is.
        KeyCode::Backspace => {
            if app.input.pop().is_none() {
                app.attached.pop();
            }
        }
        KeyCode::Enter => {
            let lines = app.submit();
            if !lines.is_empty() {
                // Back to following the tail: you sent something, you want to
                // see the answer.
                app.scroll_back = 0;
            }
            for line in lines {
                if typed.send(line).await.is_err() {
                    return Ok(true);
                }
            }
        }
        KeyCode::PageUp => app.scroll(app.page() as isize),
        KeyCode::PageDown => app.scroll(-(app.page() as isize)),
        KeyCode::End => app.scroll_back = 0,
        _ => {}
    }
    Ok(false)
}

fn draw(frame: &mut ratatui::Frame, app: &mut App) {
    let [header, body, input] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(3),
    ])
    .areas(frame.area());

    // ---- header ----
    let follow = if app.scroll_back == 0 { "" } else { "  [scrolled]" };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" murmure  {} ", app.title),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {}{follow}", app.status),
                Style::default().fg(Color::DarkGray),
            ),
        ])),
        header,
    );

    // ---- history ----
    //
    // Anchored on the *bottom*: the newest line must always be the last visible
    // row. `Paragraph` renders top-down and clips whatever overflows the bottom,
    // so picking "the last N entries" is not enough — with wrapping on, a
    // 62-character address occupies two or three rows, the selection overflows,
    // and the newest lines are drawn past the edge and never seen.
    let inner_w = body.width.saturating_sub(2).max(1) as usize;
    let inner_h = body.height.saturating_sub(2) as usize;
    // Remembered for the next keypress: paging and clamping both need to know
    // how tall a screen is and how wide a row wraps.
    app.viewport = (inner_w, inner_h);
    // A terminal that just got narrower turns entries into more rows, which can
    // leave the offset pointing past the oldest one.
    app.scroll(0);
    let (start, end, hidden_rows) = window(&app.history, inner_w, inner_h, app.scroll_back);

    let lines: Vec<Line> = app
        .history
        .iter()
        .skip(start)
        .take(end - start)
        .map(|entry| Line::styled(entry.text.clone(), style_for(entry.kind)))
        .collect();

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((hidden_rows, 0))
            .block(Block::default().borders(Borders::ALL)),
        body,
    );

    // ---- input ----
    //
    // Visibly dead until Tor is up. The box says so, the border is dim, and
    // there is no cursor — three signals that typing now would go nowhere.
    let (title, border, body_style) = if app.accepting {
        (
            " type, Enter to send ".to_owned(),
            Style::default().fg(Color::Cyan),
            Style::default(),
        )
    } else {
        (
            format!(" {} — please wait ", app.status),
            Style::default().fg(Color::DarkGray),
            Style::default().fg(Color::DarkGray),
        )
    };

    let shown = app.input_display();
    frame.render_widget(
        Paragraph::new(shown.as_str()).style(body_style).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(border),
        ),
        input,
    );

    // Put the real cursor where the text is, so the terminal's own blink is the
    // cursor and there is nothing to draw. No cursor while input is refused.
    if app.accepting {
        let cursor_x = input.x + 1 + shown.chars().count() as u16;
        frame.set_cursor_position((cursor_x.min(input.right().saturating_sub(2)), input.y + 1));
    }
}

/// Put text on the system clipboard, by asking the terminal to do it.
///
/// # Why an escape sequence and not a clipboard library
///
/// OSC 52 is a request the terminal answers on our behalf, so it needs no X11,
/// no Wayland and no pasteboard API — which means no platform-specific build
/// dependency, and it keeps working over SSH, where a clipboard library would be
/// writing to the clipboard of the wrong machine.
///
/// It is best effort. A terminal that does not implement it, or that has it
/// switched off for security — some do, because a program that can write your
/// clipboard can also overwrite what you were about to paste — ignores the
/// sequence. There is no reply, so there is nothing to check.
///
/// ponytail: no chunking. The sequence goes through the terminal's input buffer
/// and long payloads get truncated somewhere around 100 kB; an address and a key
/// are 120 bytes.
fn copy_to_clipboard(text: &str) {
    use std::io::Write as _;

    let encoded = data_encoding::BASE64.encode(text.as_bytes());
    let mut out = std::io::stdout();
    // `c` is the selection: the clipboard proper, not the X11 primary selection.
    let _ = write!(out, "\x1b]52;c;{encoded}\x07");
    let _ = out.flush();
}

/// Is this paste a file dropped on the window? If so, where it lives.
///
/// Terminals hand a dropped file over as its path, escaped for a shell that is
/// not there: GNOME Terminal and Konsole quote it, iTerm2 and Terminal.app
/// backslash-escape the spaces, some prepend `file://`. Undo all of that, then
/// let the filesystem decide — a path that resolves to a real file was a drop,
/// anything else was a paste of text that happened to look like one.
fn as_dropped_file(text: &str) -> Option<PathBuf> {
    let raw = text.trim();
    if raw.is_empty() || raw.contains('\n') {
        return None;
    }

    // Quoted whole, which is what a path with spaces usually arrives as.
    let unquoted = match (raw.chars().next(), raw.chars().last()) {
        (Some('\''), Some('\'')) | (Some('"'), Some('"')) if raw.chars().count() > 1 => {
            &raw[1..raw.len() - 1]
        }
        _ => raw,
    };

    // A `file://` URL, which is what a Wayland drop can produce. Only the
    // localhost form: anything else is not a local path.
    let stripped = unquoted
        .strip_prefix("file://localhost")
        .or_else(|| unquoted.strip_prefix("file://"))
        .unwrap_or(unquoted);

    // Backslash escapes. Dropping the backslash is right for `\ ` and `\'`, and
    // for a literal backslash in a name it is the escaped form that arrived.
    let mut path = String::with_capacity(stripped.len());
    let mut chars = stripped.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => path.push(chars.next().unwrap_or('\\')),
            c => path.push(c),
        }
    }

    let expanded = match path.strip_prefix("~/") {
        Some(rest) => PathBuf::from(std::env::var_os("HOME")?).join(rest),
        None => PathBuf::from(&path),
    };
    // The filesystem is the judge, not the shape of the string.
    expanded.is_file().then_some(expanded)
}

/// How many rows one entry occupies once wrapped to `width`.
///
/// Counts characters, not grapheme clusters or display width. Close enough for
/// the accented Latin text this carries, and it can only ever be off by a row —
/// never panic, never lose the newest line.
fn rows_for(text: &str, width: usize) -> usize {
    text.chars().count().div_ceil(width).max(1)
}

/// Pick the slice of history to draw, anchored `scroll_back` rows above the
/// bottom.
///
/// Returns the half-open entry range and how many rows of the *first* entry to
/// hide. `Paragraph` renders top-down from that offset and clips at the bottom
/// edge, so a partly visible entry works at either end without help.
fn window(
    history: &VecDeque<Entry>,
    width: usize,
    height: usize,
    scroll_back: usize,
) -> (usize, usize, u16) {
    if height == 0 || history.is_empty() {
        return (history.len(), history.len(), 0);
    }

    // The whole history is one column of rows. Work out which row sits at the
    // top of the box, then find the entry it falls inside.
    let total: usize = history.iter().map(|e| rows_for(&e.text, width)).sum();
    let top = total.saturating_sub(scroll_back + height);

    let mut start = 0usize;
    let mut above = 0usize;
    for entry in history.iter() {
        let rows = rows_for(&entry.text, width);
        if above + rows > top {
            break;
        }
        above += rows;
        start += 1;
    }

    // Take just enough entries to fill the box. Anything past the bottom edge
    // would be drawn and clipped, which costs work and changes nothing.
    let mut end = start;
    let mut drawn = 0usize;
    for entry in history.iter().skip(start) {
        drawn += rows_for(&entry.text, width);
        end += 1;
        if drawn >= top - above + height {
            break;
        }
    }

    (start, end, u16::try_from(top - above).unwrap_or(u16::MAX))
}

fn style_for(kind: Kind) -> Style {
    match kind {
        Kind::System => Style::default().fg(Color::DarkGray),
        Kind::Mine => Style::default().fg(Color::Cyan),
        Kind::Theirs => Style::default().fg(Color::Green),
        Kind::Error => Style::default().fg(Color::Red),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(text: &str) -> Entry {
        Entry {
            kind: Kind::System,
            text: text.to_owned(),
        }
    }

    /// The bug this whole function exists for: long lines wrap, the selection
    /// overflows the box, and the newest line gets clipped off the bottom.
    #[test]
    fn the_newest_line_is_always_visible_however_long_the_others_are() {
        let width = 20;
        let height = 5;

        let mut history = VecDeque::new();
        // Three entries that each wrap to three rows: nine rows for a five-row
        // box.
        for _ in 0..3 {
            history.push_back(entry(&"x".repeat(width * 3)));
        }
        history.push_back(entry("the newest line"));

        let (start, end, hidden) = window(&history, width, height, 0);
        assert_eq!(end, history.len(), "the newest entry must be included");
        assert!(start < end);

        // Rows actually drawn, minus the ones scrolled off the top, must fit.
        let drawn: usize = history
            .iter()
            .skip(start)
            .take(end - start)
            .map(|e| rows_for(&e.text, width))
            .sum();
        assert_eq!(drawn - hidden as usize, height);
    }

    /// A dropped file is recognised however the terminal escaped it, and a
    /// paste that merely looks like a path is not.
    #[test]
    fn a_dropped_file_is_told_apart_from_pasted_text() {
        let dir = std::env::temp_dir().join(format!("murmure-drop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let spaced = dir.join("mon rapport.pdf");
        std::fs::write(&spaced, b"x").unwrap();
        let plain = dir.join("image.png");
        std::fs::write(&plain, b"x").unwrap();

        let d = dir.display();
        for form in [
            format!("{d}/image.png"),
            format!("  {d}/image.png  "),
            format!("'{d}/image.png'"),
            format!("\"{d}/image.png\""),
            format!("file://{d}/image.png"),
        ] {
            assert_eq!(as_dropped_file(&form), Some(plain.clone()), "{form}");
        }
        // Spaces, escaped the two ways terminals escape them.
        assert_eq!(
            as_dropped_file(&format!("{d}/mon\\ rapport.pdf")),
            Some(spaced.clone())
        );
        assert_eq!(
            as_dropped_file(&format!("'{d}/mon rapport.pdf'")),
            Some(spaced)
        );

        // Text that is not a file stays text, however path-shaped.
        assert_eq!(as_dropped_file("/etc/passwd/nope"), None);
        assert_eq!(as_dropped_file("bonjour tout le monde"), None);
        assert_eq!(as_dropped_file(""), None);
        // A directory is not something to send.
        assert_eq!(as_dropped_file(&d.to_string()), None);
        // Several lines is a paste, whatever the first one is.
        assert_eq!(as_dropped_file(&format!("{d}/image.png\nsecond line")), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What the box shows is the file's name; what Enter sends is its path.
    #[test]
    fn an_attachment_shows_as_a_name_and_submits_as_a_command() {
        let mut app = App::new("t".into());
        app.attached.push(PathBuf::from("/tmp/mes docs/image.png"));
        app.input.push_str("tiens");

        assert_eq!(app.input_display(), "[image.png] tiens");
        assert_eq!(
            app.submit(),
            vec!["/send /tmp/mes docs/image.png".to_owned(), "tiens".to_owned()]
        );
        // Submitting empties both, so the next line starts clean.
        assert!(app.attached.is_empty());
        assert!(app.input.is_empty());
        assert!(app.submit().is_empty(), "nothing to send is nothing sent");
    }

    /// A pasted paragraph is one line, not several submissions.
    #[test]
    fn a_multi_line_paste_stays_one_line() {
        let mut app = App::new("t".into());
        app.paste("deux\nlignes\r\ncollees");
        assert_eq!(app.input, "deux lignes  collees");
        assert!(app.attached.is_empty());
    }

    #[test]
    fn wrapped_height_counts_every_row() {
        assert_eq!(rows_for("", 10), 1, "an empty line still takes a row");
        assert_eq!(rows_for("short", 10), 1);
        assert_eq!(rows_for(&"x".repeat(10), 10), 1);
        assert_eq!(rows_for(&"x".repeat(11), 10), 2);
        assert_eq!(rows_for(&"x".repeat(30), 10), 3);
    }

    #[test]
    fn an_empty_or_zero_sized_window_does_not_panic() {
        let empty = VecDeque::new();
        assert_eq!(window(&empty, 20, 5, 0), (0, 0, 0));

        let mut one = VecDeque::new();
        one.push_back(entry("hello"));
        assert_eq!(window(&one, 20, 0, 0), (1, 1, 0));
        // Scrolled back further than the history is tall. `App::scroll` clamps
        // so this cannot arrive from the keyboard, but a window that answered
        // with an empty range would blank the box instead of pinning to the top.
        assert_eq!(window(&one, 20, 5, 99), (0, 1, 0));
    }

    #[test]
    fn scrollback_is_bounded_and_drops_the_oldest() {
        let mut app = App::new("t".into());
        for i in 0..SCROLLBACK + 10 {
            app.push(entry(&i.to_string()));
        }
        assert_eq!(app.history.len(), SCROLLBACK);
        assert_eq!(app.history.front().unwrap().text, "10");
    }

    /// Lines falling off the top must not shift what the operator is reading.
    #[test]
    fn the_view_stays_anchored_while_old_lines_fall_off() {
        let mut app = App::new("t".into());
        for i in 0..SCROLLBACK {
            app.push(entry(&i.to_string()));
        }
        app.scroll_back = 50;
        app.push(entry("new"));
        assert_eq!(app.scroll_back, 49);
    }

    /// Holding a scroll key must never run past either end.
    #[test]
    fn scrolling_never_runs_past_the_history() {
        let mut app = App::new("t".into());
        app.viewport = (80, 3);
        for i in 0..5 {
            app.push(entry(&i.to_string()));
        }

        // Five rows in a three-row box: two rows of travel, and no more.
        app.scroll(app.page() as isize);
        assert_eq!(app.scroll_back, 2, "cannot scroll past the oldest row");
        app.scroll(app.page() as isize);
        assert_eq!(app.scroll_back, 2);

        app.scroll(-(app.page() as isize));
        assert_eq!(app.scroll_back, 0, "cannot scroll past the newest row");
        app.scroll(-1);
        assert_eq!(app.scroll_back, 0);
    }

    /// History that fits on screen has nothing to scroll.
    #[test]
    fn a_short_history_does_not_move() {
        let mut app = App::new("t".into());
        app.viewport = (80, 10);
        app.push(entry("only line"));
        app.scroll(5);
        assert_eq!(app.scroll_back, 0);
    }

    /// The bug this replaced: one press of Up moved the view by however many
    /// rows the next entry happened to wrap to.
    #[test]
    fn one_press_moves_exactly_one_row_however_long_the_lines_are() {
        let mut app = App::new("t".into());
        app.viewport = (10, 2);
        // 4 rows, then 1: five rows of history in a two-row box.
        app.push(entry(&"x".repeat(40)));
        app.push(entry("short"));

        app.scroll(1);
        assert_eq!(app.scroll_back, 1);
        app.scroll(1);
        assert_eq!(app.scroll_back, 2, "a wrapped entry is not one step");

        // The top row of the box walks up the wrapped entry one row at a time.
        // At scroll_back 1 the short line has left the bottom of the box, so
        // only the wrapped entry is drawn, from its third row.
        for (back, expect) in [(0, (0, 2, 3)), (1, (0, 1, 2)), (3, (0, 1, 0))] {
            assert_eq!(window(&app.history, 10, 2, back), expect, "scroll_back {back}");
        }
    }
}
