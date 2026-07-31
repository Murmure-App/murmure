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

use anyhow::{Context as _, Result};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
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

/// How many lines a PageUp/PageDown moves.
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
    /// Lines scrolled up from the bottom. Zero means following the tail.
    scroll_back: usize,
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
            scroll_back: 0,
            accepting: false,
        }
    }

    /// Move the view: positive scrolls back into history, negative comes
    /// forward. Clamped at both ends, so holding a key never overshoots.
    fn scroll(&mut self, lines: isize) {
        let moved = self.scroll_back as isize + lines;
        self.scroll_back = moved.clamp(0, self.history.len() as isize) as usize;
    }

    fn push(&mut self, entry: Entry) {
        self.history.push_back(entry);
        while self.history.len() > SCROLLBACK {
            self.history.pop_front();
            // Keep the view anchored on the same text as lines fall off the top.
            self.scroll_back = self.scroll_back.saturating_sub(1);
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
    let result = event_loop(&mut terminal, &mut updates, typed, title).await;
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

    terminal.draw(|frame| draw(frame, &app)).context("drawing")?;

    loop {
        tokio::select! {
            update = updates.recv() => {
                match update {
                    Some(Update::Line(entry)) => app.push(entry),
                    Some(Update::Status(status)) => app.status = status,
                    Some(Update::Accepting(yes)) => app.accepting = yes,
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
                    // Resize and mouse events just need a redraw.
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e).context("reading a terminal event"),
                    None => return Ok(()),
                }
            }
        }

        terminal.draw(|frame| draw(frame, &app)).context("drawing")?;
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
        KeyCode::Char('u') if ctrl => app.input.clear(),
        // Scrolling, bound to keys every keyboard has. A MacBook has no
        // PageUp/PageDown/End except through Fn, so the arrows and the
        // less(1) conventions carry the feature; the named keys stay as
        // aliases for keyboards that have them.
        KeyCode::Char('b') if ctrl => app.scroll(PAGE as isize),
        KeyCode::Char('f') if ctrl => app.scroll(-(PAGE as isize)),
        KeyCode::Char('e') if ctrl => app.scroll_back = 0,
        KeyCode::Up => app.scroll(1),
        KeyCode::Down => app.scroll(-1),
        KeyCode::Char(c) => app.input.push(c),
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Enter => {
            let line = std::mem::take(&mut app.input);
            if !line.trim().is_empty() {
                // Back to following the tail: you sent something, you want to
                // see the answer.
                app.scroll_back = 0;
                if typed.send(line).await.is_err() {
                    return Ok(true);
                }
            }
        }
        KeyCode::PageUp => app.scroll(PAGE as isize),
        KeyCode::PageDown => app.scroll(-(PAGE as isize)),
        KeyCode::End => app.scroll_back = 0,
        _ => {}
    }
    Ok(false)
}

fn draw(frame: &mut ratatui::Frame, app: &App) {
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

    frame.render_widget(
        Paragraph::new(app.input.as_str()).style(body_style).block(
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
        let cursor_x = input.x + 1 + app.input.chars().count() as u16;
        frame.set_cursor_position((cursor_x.min(input.right().saturating_sub(2)), input.y + 1));
    }
}

/// How many rows one entry occupies once wrapped to `width`.
///
/// Counts characters, not grapheme clusters or display width. Close enough for
/// the accented Latin text this carries, and it can only ever be off by a row —
/// never panic, never lose the newest line.
fn rows_for(text: &str, width: usize) -> usize {
    text.chars().count().div_ceil(width).max(1)
}

/// Pick the slice of history to draw, anchored on the bottom.
///
/// Returns the half-open entry range and how many rows of the *first* entry to
/// hide, so that the last visible row is the newest line rather than whatever
/// happened to fit.
fn window(
    history: &VecDeque<Entry>,
    width: usize,
    height: usize,
    scroll_back: usize,
) -> (usize, usize, u16) {
    let end = history.len().saturating_sub(scroll_back);
    if height == 0 || end == 0 {
        return (end, end, 0);
    }

    // Walk backwards from the newest visible entry, adding wrapped heights
    // until the box is full.
    let mut start = end;
    let mut rows = 0usize;
    for entry in history.iter().take(end).rev() {
        rows += rows_for(&entry.text, width);
        start -= 1;
        if rows >= height {
            break;
        }
    }

    // If the topmost entry only half fits, hide its first rows rather than
    // pushing the newest line off the bottom.
    let hidden = u16::try_from(rows.saturating_sub(height)).unwrap_or(u16::MAX);
    (start, end, hidden)
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
        // Scrolled back further than the history is long.
        assert_eq!(window(&one, 20, 5, 99), (0, 0, 0));
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
        for i in 0..5 {
            app.push(entry(&i.to_string()));
        }

        app.scroll(PAGE as isize);
        assert_eq!(app.scroll_back, 5, "cannot scroll past the oldest line");
        app.scroll(PAGE as isize);
        assert_eq!(app.scroll_back, 5);

        app.scroll(-(PAGE as isize));
        assert_eq!(app.scroll_back, 0, "cannot scroll past the newest line");
        app.scroll(-1);
        assert_eq!(app.scroll_back, 0);
    }
}
