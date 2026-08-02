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
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture, Event,
    EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use futures::StreamExt as _;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
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

/// Rows one notch of the mouse wheel moves.
const WHEEL_STEP: usize = 3;

/// How long a header note stays up. Long enough to catch out of the corner of
/// an eye, short enough not to be mistaken for state.
const FLASH_FOR: Duration = Duration::from_secs(2);

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

/// One on-screen row, wrapped from an [`Entry`] in [`App::history`].
///
/// This is the single source of truth for "what is on screen where": the same
/// `Vec<Row>` is used to draw, to resolve a mouse click to a piece of text, and
/// to page-scroll — so those three can never disagree with each other the way
/// a separate row-counting approximation could.
#[derive(Debug, Clone)]
struct Row {
    /// Index into `history` this row was wrapped from. Consecutive rows that
    /// share this join back into their entry's original text with no
    /// separator — that is what makes a selected address come back whole
    /// however it happened to wrap on screen.
    entry: usize,
    /// Char offset within that entry's text where this row starts.
    offset: usize,
    kind: Kind,
    text: String,
}

/// One end of a mouse selection: which entry, and how far into its text.
///
/// Anchored to the *entry*, not to a screen row or a `(row, col)` pair. A
/// screen row's meaning changes the instant the view scrolls, but an entry
/// index does not — so a selection survives new messages arriving mid-drag,
/// the same way scrolling a real terminal's history does not lose its
/// selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Anchor {
    entry: usize,
    offset: usize,
}

/// A mouse-drag text selection: where it started, and where the mouse is (or
/// was, once released) now.
#[derive(Debug, Clone, Copy)]
struct Selection {
    anchor: Anchor,
    current: Anchor,
}

impl Selection {
    /// The two ends in document order, earliest first.
    ///
    /// `(entry, offset)` sorts correctly because entries are chronological and
    /// a row's offset only increases left-to-right within one entry — so
    /// lexicographic order on the pair is reading order, regardless of which
    /// direction the mouse actually dragged.
    fn ordered(&self) -> (Anchor, Anchor) {
        let a = (self.anchor.entry, self.anchor.offset);
        let b = (self.current.entry, self.current.offset);
        if a <= b {
            (self.anchor, self.current)
        } else {
            (self.current, self.anchor)
        }
    }
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
    /// Where the text cursor sits in [`Self::input`], as a byte index on a char
    /// boundary. Kept as bytes because that is what `String::insert` and
    /// `String::remove` take; every move goes through a boundary search, so it
    /// can never land mid-character.
    cursor: usize,
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
    /// Where the history box's *inner* area starts on screen, as of the last
    /// frame — the coordinate a mouse event's `(column, row)` is measured
    /// against to find which [`Row`] it landed on.
    body_origin: (u16, u16),
    /// The rows drawn last frame, in on-screen order. A mouse click is
    /// resolved against exactly this, not recomputed, so a selection always
    /// matches pixels the operator actually saw.
    rows: Vec<Row>,
    /// The current text selection, if any. Sticks around after the mouse is
    /// released so the highlight stays visible, and is replaced or cleared by
    /// the next press.
    selection: Option<Selection>,
    /// Set while the left button is held down over the history, so a `Drag`
    /// event extends the existing selection instead of starting a new one —
    /// crossterm can deliver a stray `Drag` without a matching `Down` on some
    /// terminals, and this is what tells that apart from a real one.
    dragging: bool,
    /// A short note in the header, and when it stops being shown.
    ///
    /// Exists because OSC 52 is fire-and-forget: the terminal never replies, so
    /// a copy that silently did nothing looks exactly like one that worked.
    /// Saying how many characters went out is the only confirmation available,
    /// and it doubles as a check that the selection was what the operator
    /// thought it was.
    flash: Option<(String, Instant)>,
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
            cursor: 0,
            attached: Vec::new(),
            scroll_back: 0,
            viewport: (80, PAGE),
            body_origin: (0, 0),
            rows: Vec::new(),
            selection: None,
            dragging: false,
            flash: None,
            accepting: false,
        }
    }

    /// Show a note in the header for [`FLASH_FOR`].
    fn flash(&mut self, text: impl Into<String>) {
        self.flash = Some((text.into(), Instant::now() + FLASH_FOR));
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
                '\n' | '\r' => self.insert(' '),
                c if c.is_control() => {}
                c => self.insert(c),
            }
        }
    }

    /// Type one character where the cursor is.
    fn insert(&mut self, c: char) {
        self.input.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    /// Delete the character before the cursor. `false` when there was none.
    fn backspace(&mut self) -> bool {
        let Some(prev) = self.input[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
        else {
            return false;
        };
        self.input.remove(prev);
        self.cursor = prev;
        true
    }

    /// Move the cursor one character left or right, stopping at either end.
    fn move_cursor(&mut self, right: bool) {
        self.cursor = if right {
            self.input[self.cursor..]
                .char_indices()
                .nth(1)
                .map_or(self.input.len(), |(i, _)| self.cursor + i)
        } else {
            self.input[..self.cursor]
                .char_indices()
                .next_back()
                .map_or(0, |(i, _)| i)
        };
    }

    /// What the input box shows: what is being typed, then the attachments.
    ///
    /// Attachments come last because they are the most recent thing that
    /// happened — dropping a file on `/send` used to render `[image.jpg] /send`,
    /// which reads backwards. Putting them after the text also keeps them clear
    /// of the cursor, which only ever moves inside the typed part.
    fn input_display(&self) -> String {
        let mut shown = self.input.clone();
        for path in &self.attached {
            let name = path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy();
            if !shown.is_empty() && !shown.ends_with(' ') {
                shown.push(' ');
            }
            shown.push_str(&format!("[{name}]"));
        }
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
        self.cursor = 0;
        // Typing `/send` and *then* dropping a file is the obvious way to try
        // it. The chips already carry the whole command, so the bare verb left
        // over would only produce "usage: /send <path>" after the file went.
        let redundant = !lines.is_empty() && text.trim() == "/send";
        if !text.trim().is_empty() && !redundant {
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
    // Mouse capture is what lets murmure draw its own selection highlight and
    // copy it on release. The trade-off, and it is a real one: the terminal's
    // own native selection stops working while this is on, because the
    // terminal no longer sees clicks and drags at all — they come here
    // instead. Shift-drag is every terminal's escape hatch back to its own
    // selection, for selecting scrollback murmure itself does not keep.
    let mouse = crossterm::execute!(std::io::stdout(), EnableMouseCapture).is_ok();

    let result = event_loop(&mut terminal, &mut updates, typed, title).await;

    if mouse {
        let _ = crossterm::execute!(std::io::stdout(), DisableMouseCapture);
    }
    if bracketed {
        // Leaving it on would make the shell after us receive pastes wrapped in
        // escape sequences it does not expect.
        let _ = crossterm::execute!(std::io::stdout(), DisableBracketedPaste);
    }
    ratatui::restore();
    result
}

/// Wait until `deadline`, or forever when there is nothing to wait for.
///
/// `pending()` rather than a long sleep: a select branch that never completes
/// costs nothing, while a poll every so often would wake the interface up for
/// no reason on a machine that is meant to sit idle for hours.
async fn expire_at(deadline: Option<Instant>) {
    match deadline {
        Some(t) => tokio::time::sleep_until(tokio::time::Instant::from_std(t)).await,
        None => std::future::pending().await,
    }
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
        // Read before the select: the branch below cannot borrow `app` while
        // the other branches hold it mutably.
        let flash_until = app.flash.as_ref().map(|(_, until)| *until);

        tokio::select! {
            // Armed only while a header note is up, so it never fires
            // otherwise. Without it the note would stay on screen until the
            // next keypress — the loop has no periodic tick, and a copy is
            // precisely the moment when the operator touches nothing.
            () = expire_at(flash_until) => {}

            update = updates.recv() => {
                match update {
                    Some(Update::Line(entry)) => app.push(entry),
                    Some(Update::Status(status)) => app.status = status,
                    Some(Update::Accepting(yes)) => app.accepting = yes,
                    Some(Update::Clipboard(text)) => {
                        copy_to_clipboard(&text);
                        app.flash(format!("copied {} chars", text.chars().count()));
                    }
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
                        Update::Clipboard(text) => {
                            copy_to_clipboard(&text);
                            app.flash(format!("copied {} chars", text.chars().count()));
                        }
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
                    Some(Ok(Event::Mouse(m))) => handle_mouse(m, &mut app),
                    // A resize just needs a redraw.
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
    if !app.accepting
        && !matches!(
            key.code,
            KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown
        )
    {
        return Ok(false);
    }

    match key.code {
        KeyCode::Char('u') if ctrl => {
            app.input.clear();
            app.cursor = 0;
            app.attached.clear();
        }
        // Ctrl-V, because a terminal reserves Ctrl-Shift-V for itself and
        // reaching for Shift on every paste is exactly the friction this
        // removes. It goes through the same path as a real paste, so a copied
        // file path becomes an attachment here too.
        KeyCode::Char('v') if ctrl => {
            if let Some(text) = read_clipboard().await {
                app.paste(&text);
            }
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
        KeyCode::Char(c) => app.insert(c),
        // Editing inside the line, not just at its end. A 62-character address
        // with one wrong character used to mean clearing the lot and starting
        // over.
        KeyCode::Left => app.move_cursor(false),
        KeyCode::Right => app.move_cursor(true),
        KeyCode::Home => app.cursor = 0,
        // End belongs to the input box; Ctrl-E is the one that jumps the history
        // back to the newest line, and it is the one the help names.
        KeyCode::End => app.cursor = app.input.len(),
        // Once the text is gone, Backspace takes attachments off the end, so a
        // file dropped by mistake is removed the way anything else is.
        KeyCode::Backspace => {
            if !app.backspace() {
                app.attached.pop();
            }
        }
        KeyCode::Delete => {
            if app.cursor < app.input.len() {
                app.input.remove(app.cursor);
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
    // Expired notes are dropped here rather than in the event loop, so a frame
    // drawn for any other reason also clears a stale one.
    if app.flash.as_ref().is_some_and(|(_, until)| Instant::now() >= *until) {
        app.flash = None;
    }
    let mut spans = vec![
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
    ];
    if let Some((note, _)) = &app.flash {
        spans.push(Span::styled(
            format!("  {note}"),
            Style::default().fg(Color::Cyan),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), header);

    // ---- history ----
    //
    // Anchored on the *bottom*: the newest line must always be the last visible
    // row. Wrapping is done by hand (see [`visible_rows`]) rather than left to
    // `Paragraph`'s own word-wrap, so the row a mouse click lands on is exactly
    // the row that got drawn — a second wrapping pass that came out even one
    // row different would point a click at the wrong text.
    let inner_w = body.width.saturating_sub(2).max(1) as usize;
    let inner_h = body.height.saturating_sub(2) as usize;
    // Remembered for the next keypress: paging and clamping both need to know
    // how tall a screen is and how wide a row wraps.
    app.viewport = (inner_w, inner_h);
    app.body_origin = (body.x + 1, body.y + 1);
    // A terminal that just got narrower turns entries into more rows, which can
    // leave the offset pointing past the oldest one.
    app.scroll(0);
    app.rows = visible_rows(&app.history, inner_w, inner_h, app.scroll_back);

    let lines: Vec<Line> = app
        .rows
        .iter()
        .map(|row| build_line(row, &app.selection))
        .collect();

    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL)),
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
        // Counted over the typed text only, up to the cursor. The attachment
        // chips are drawn after it, so they never shift it.
        let before = app.input[..app.cursor].chars().count() as u16;
        let cursor_x = input.x + 1 + before;
        frame.set_cursor_position((cursor_x.min(input.right().saturating_sub(2)), input.y + 1));
    }
}

/// Read the system clipboard, by asking whatever tool owns it.
///
/// # Why a subprocess and not a clipboard crate
///
/// The Rust clipboard crates link against X11 or Wayland, which turns a build
/// that works everywhere into one that needs development headers installed on
/// Linux. The tools below already exist on any machine that has a clipboard at
/// all, and calling them costs a process and no build dependency.
///
/// Tried in order, first one that produces something wins. A machine with no
/// clipboard tool — a bare TTY, a container — returns `None`, and Ctrl-V then
/// does nothing rather than failing loudly.
///
/// Over SSH this reads the *remote* clipboard, which is usually empty. That is
/// the same limitation every terminal program has, and the terminal's own paste
/// (Ctrl-Shift-V, or middle click) is the one that reaches your real clipboard.
async fn read_clipboard() -> Option<String> {
    /// A clipboard tool that hangs must not take the interface with it.
    const PATIENCE: Duration = Duration::from_millis(500);

    const TOOLS: [(&str, &[&str]); 5] = [
        ("pbpaste", &[]),
        ("wl-paste", &["--no-newline"]),
        ("xclip", &["-selection", "clipboard", "-o"]),
        ("xsel", &["--clipboard", "--output"]),
        (
            "powershell.exe",
            &["-NoProfile", "-Command", "Get-Clipboard"],
        ),
    ];

    for (tool, args) in TOOLS {
        let run = tokio::process::Command::new(tool)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output();
        let Ok(Ok(out)) = tokio::time::timeout(PATIENCE, run).await else {
            continue;
        };
        if !out.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if !text.is_empty() {
            return Some(text);
        }
    }
    None
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
    // Under test the encoding still runs, but the sequence stays off stdout:
    // `cargo test` would otherwise overwrite the clipboard of whoever ran it,
    // and scatter escape sequences through the test output.
    if cfg!(test) {
        return;
    }
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

/// Split `text` into rows of at most `width` characters, each paired with the
/// char offset where it starts.
///
/// Hard-wrapped, not word-wrapped: chat lines are short enough that breaking
/// mid-word costs nothing, and hard-wrapping is exact — a row is precisely
/// `width` characters until the last one — which is what lets [`visible_rows`]
/// find the row under a mouse click by arithmetic instead of by re-running a
/// word-wrap algorithm and hoping it agrees with what was drawn.
///
/// Counts characters, not grapheme clusters or display width. Close enough for
/// the accented Latin text this carries.
fn wrap(text: &str, width: usize) -> Vec<(usize, &str)> {
    let width = width.max(1);
    if text.is_empty() {
        return vec![(0, text)];
    }
    let bounds: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
    let mut rows = Vec::with_capacity(bounds.len().div_ceil(width));
    let mut i = 0;
    while i < bounds.len() {
        let end_i = (i + width).min(bounds.len());
        let end_byte = bounds.get(end_i).copied().unwrap_or(text.len());
        rows.push((i, &text[bounds[i]..end_byte]));
        i = end_i;
    }
    rows
}

/// How many rows one entry occupies once wrapped to `width`.
fn rows_for(text: &str, width: usize) -> usize {
    wrap(text, width).len()
}

/// Every row a `height`-tall, `width`-wide box shows, anchored `scroll_back`
/// rows above the bottom.
///
/// Rows come back whole — never a fraction of one hanging off the top edge —
/// which is the piece the old ratatui-`Wrap`-plus-scroll-offset approach
/// could not give without extra bookkeeping: that scheme drew a partial row on
/// purpose (see the removed `hidden_rows`). Owning the wrap makes "row zero of
/// what's drawn" and "row zero of what a mouse click can land on" the same
/// row, with nothing to keep in sync between them.
fn visible_rows(
    history: &VecDeque<Entry>,
    width: usize,
    height: usize,
    scroll_back: usize,
) -> Vec<Row> {
    if height == 0 || history.is_empty() {
        return Vec::new();
    }
    let needed = scroll_back + height;

    // Wrap from the newest entry backwards, stopping once enough rows exist to
    // cover the window asked for — touches a couple of screens' worth of
    // entries, never the whole scrollback.
    let mut rows_rev: Vec<Row> = Vec::new();
    for (idx, entry) in history.iter().enumerate().rev() {
        let mut this_entry: Vec<Row> = wrap(&entry.text, width)
            .into_iter()
            .rev()
            .map(|(offset, s)| Row {
                entry: idx,
                offset,
                kind: entry.kind,
                text: s.to_owned(),
            })
            .collect();
        rows_rev.append(&mut this_entry);
        if rows_rev.len() >= needed {
            break;
        }
    }
    rows_rev.reverse();

    // Scrolled further back than there is history to show: pin to the oldest
    // row rather than answering with an empty window, which would blank the box
    // instead. `App::scroll` clamps to this same limit, so a scroll key cannot
    // get here — but a terminal *resize* can: narrowing the window rewraps every
    // entry into more rows, and widening it into fewer, leaving the stored
    // `scroll_back` stale until the next keypress.
    let total = rows_rev.len();
    let scroll_back = scroll_back.min(total.saturating_sub(height));
    let end = total.saturating_sub(scroll_back);
    let start = end.saturating_sub(height);
    rows_rev[start..end].to_vec()
}

/// A row as a [`Line`], with the part inside `selection` (if any of it falls
/// on this row) drawn reversed.
fn build_line(row: &Row, selection: &Option<Selection>) -> Line<'static> {
    let base = style_for(row.kind);
    let whole = || Line::styled(row.text.clone(), base);

    let Some(sel) = selection else { return whole() };
    let (from, to) = sel.ordered();
    if row.entry < from.entry || row.entry > to.entry {
        return whole();
    }

    let len = row.text.chars().count();
    let row_end = row.offset + len;
    let sel_start = (if row.entry == from.entry { from.offset } else { 0 }).clamp(row.offset, row_end);
    let sel_end = (if row.entry == to.entry { to.offset } else { row_end }).clamp(row.offset, row_end);
    if sel_start >= sel_end {
        return whole();
    }

    let chars: Vec<char> = row.text.chars().collect();
    let (local_start, local_end) = (sel_start - row.offset, sel_end - row.offset);
    let highlight = base.add_modifier(Modifier::REVERSED);
    Line::from(vec![
        Span::styled(chars[..local_start].iter().collect::<String>(), base),
        Span::styled(chars[local_start..local_end].iter().collect::<String>(), highlight),
        Span::styled(chars[local_end..].iter().collect::<String>(), base),
    ])
}

/// Resolve a mouse position to the [`Row`] it lands on, if any, as an
/// [`Anchor`] into that row's entry.
///
/// Clamps rather than refusing: dragging above, left of, or below the box is
/// how a selection is extended past the visible edge in every terminal, and
/// clamping to the nearest row and column is what makes that keep working
/// here instead of dropping the drag.
fn anchor_at(app: &App, column: u16, row: u16) -> Option<Anchor> {
    if app.rows.is_empty() {
        return None;
    }
    let (origin_x, origin_y) = app.body_origin;
    let r = (row.saturating_sub(origin_y) as usize).min(app.rows.len() - 1);
    let c = column.saturating_sub(origin_x) as usize;

    let line = &app.rows[r];
    let local = c.min(line.text.chars().count());
    Some(Anchor {
        entry: line.entry,
        offset: line.offset + local,
    })
}

/// The text a finished selection covers, read from the *entries themselves*
/// rather than the wrapped rows — so an address selected across several rows
/// comes back as the one unbroken string it always was, never split at
/// whatever column it happened to wrap on screen. Entries are joined with a
/// newline; `None` when there is nothing left to select (an empty history, or
/// a selection whose start has already scrolled out of it).
fn selected_text(history: &VecDeque<Entry>, sel: Selection) -> Option<String> {
    let last = history.len().checked_sub(1)?;
    let (from, to) = sel.ordered();
    if from.entry > last {
        return None;
    }
    let to_entry = to.entry.min(last);

    let mut out = String::new();
    for (idx, entry) in history
        .iter()
        .enumerate()
        .take(to_entry + 1)
        .skip(from.entry)
    {
        let chars: Vec<char> = entry.text.chars().collect();
        let start = if idx == from.entry { from.offset.min(chars.len()) } else { 0 };
        let end = if idx == to.entry { to.offset.min(chars.len()) } else { chars.len() };
        if idx != from.entry {
            out.push('\n');
        }
        out.extend(&chars[start..end.max(start)]);
    }
    Some(out).filter(|s| !s.is_empty())
}

/// React to one mouse event over the history box.
fn handle_mouse(m: MouseEvent, app: &mut App) {
    match m.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            app.dragging = false;
            app.selection = anchor_at(app, m.column, m.row).map(|a| Selection {
                anchor: a,
                current: a,
            });
        }
        MouseEventKind::Drag(MouseButton::Left) => {
            let Some(anchor) = anchor_at(app, m.column, m.row) else {
                return;
            };
            match app.selection.as_mut() {
                Some(sel) => sel.current = anchor,
                // A `Down` was missed (some terminals send a bare `Drag` for
                // the first movement), so treat this as where it started.
                None => app.selection = Some(Selection { anchor, current: anchor }),
            }
            app.dragging = true;
        }
        MouseEventKind::Up(MouseButton::Left) => {
            match app.selection {
                // Pressed and released with no movement: a plain click,
                // clearing whatever was highlighted before rather than leaving
                // a zero-width "selection" behind.
                Some(sel) if !app.dragging || sel.anchor == sel.current => {
                    app.selection = None;
                }
                Some(sel) => {
                    if let Some(text) = selected_text(&app.history, sel) {
                        copy_to_clipboard(&text);
                        let n = text.chars().count();
                        app.flash(format!("copied {n} char{}", if n == 1 { "" } else { "s" }));
                    }
                }
                None => {}
            }
            app.dragging = false;
        }
        MouseEventKind::ScrollUp => app.scroll(WHEEL_STEP as isize),
        MouseEventKind::ScrollDown => app.scroll(-(WHEEL_STEP as isize)),
        _ => {}
    }
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

        let rows = visible_rows(&history, width, height, 0);

        // Exactly a boxful, and every row whole — never a fraction of one
        // hanging off the top edge.
        assert_eq!(rows.len(), height);
        let last = rows.last().unwrap();
        assert_eq!(last.entry, history.len() - 1, "the newest entry must be included");
        assert_eq!(last.text, "the newest line");
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

    /// The cursor moves inside the line, and edits land where it is.
    #[test]
    fn the_cursor_moves_and_edits_in_the_middle() {
        let mut app = App::new("t".into());
        for c in "bonjur".chars() {
            app.insert(c);
        }
        // Two steps back from the end lands between `j` and `u`.
        app.move_cursor(false);
        app.move_cursor(false);
        app.insert('o');
        assert_eq!(app.input, "bonjour");
        assert_eq!(app.cursor, 5, "the cursor follows what was just typed");

        // Backspace takes what is before the cursor, not what is at the end.
        assert!(app.backspace());
        assert_eq!(app.input, "bonjur");

        // Neither end runs off.
        app.cursor = 0;
        app.move_cursor(false);
        assert_eq!(app.cursor, 0);
        assert!(!app.backspace(), "nothing before the start");
        app.cursor = app.input.len();
        app.move_cursor(true);
        assert_eq!(app.cursor, app.input.len());
    }

    /// Multi-byte characters must not be split by a cursor move.
    #[test]
    fn the_cursor_steps_over_whole_characters() {
        let mut app = App::new("t".into());
        for c in "éàü".chars() {
            app.insert(c);
        }
        assert_eq!(app.cursor, 6, "three two-byte characters");
        app.move_cursor(false);
        assert_eq!(app.cursor, 4);
        app.insert('x');
        assert_eq!(app.input, "éàxü");
        assert!(app.backspace());
        assert_eq!(app.input, "éàü");
    }

    /// What the box shows is the file's name; what Enter sends is its path.
    #[test]
    fn an_attachment_shows_as_a_name_and_submits_as_a_command() {
        let mut app = App::new("t".into());
        app.attached.push(PathBuf::from("/tmp/mes docs/image.png"));
        for c in "tiens".chars() {
            app.insert(c);
        }

        // The chip goes after the text, because dropping it is what just
        // happened — `[image.png] tiens` read backwards.
        assert_eq!(app.input_display(), "tiens [image.png]");
        assert_eq!(
            app.submit(),
            vec!["/send /tmp/mes docs/image.png".to_owned(), "tiens".to_owned()]
        );
        // Submitting empties both, so the next line starts clean.
        assert!(app.attached.is_empty());
        assert!(app.input.is_empty());
        assert!(app.submit().is_empty(), "nothing to send is nothing sent");
    }

    /// Typing `/send` and then dropping a file must not leave the bare verb
    /// behind, which would only produce a usage error after the file went.
    #[test]
    fn a_dropped_file_absorbs_a_typed_send() {
        let mut app = App::new("t".into());
        for c in "/send".chars() {
            app.insert(c);
        }
        app.attached.push(PathBuf::from("/tmp/image.JPG"));

        assert_eq!(app.input_display(), "/send [image.JPG]");
        assert_eq!(app.submit(), vec!["/send /tmp/image.JPG".to_owned()]);
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
        assert!(visible_rows(&empty, 20, 5, 0).is_empty());

        let mut one = VecDeque::new();
        one.push_back(entry("hello"));
        assert!(visible_rows(&one, 20, 0, 0).is_empty(), "no rows fit in no height");

        // Scrolled back further than the history is tall. `App::scroll` clamps
        // so this cannot arrive from the keyboard, but a resize leaves a stale
        // `scroll_back` behind — and answering with no rows would blank the box
        // instead of pinning to the top.
        let rows = visible_rows(&one, 20, 5, 99);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "hello");
        assert_eq!(rows[0].offset, 0);

        // A zero width must not divide by zero or loop forever either.
        assert_eq!(visible_rows(&one, 0, 5, 0).len(), "hello".len());
    }

    fn mouse(app: &mut App, kind: MouseEventKind, column: u16, row: u16) {
        handle_mouse(
            MouseEvent {
                kind,
                column,
                row,
                modifiers: KeyModifiers::NONE,
            },
            app,
        );
    }
    fn press(app: &mut App, c: u16, r: u16) {
        mouse(app, MouseEventKind::Down(MouseButton::Left), c, r);
    }
    fn drag(app: &mut App, c: u16, r: u16) {
        mouse(app, MouseEventKind::Drag(MouseButton::Left), c, r);
    }
    fn release(app: &mut App, c: u16, r: u16) {
        mouse(app, MouseEventKind::Up(MouseButton::Left), c, r);
    }

    /// A copy that produced no confirmation is indistinguishable from a copy
    /// the terminal refused, which is the whole reason the note exists.
    #[test]
    fn copying_a_selection_says_how_much_went_out() {
        let mut app = App::new("t".into());
        app.body_origin = (0, 0);
        app.viewport = (40, 4);
        app.push(entry("hello"));
        app.rows = visible_rows(&app.history, 40, 4, 0);

        // Press at the start, drag to the end, release: the copy path.
        press(&mut app, 0, 0);
        drag(&mut app, 5, 0);
        release(&mut app, 5, 0);

        let (note, until) = app.flash.as_ref().expect("a copy must say so");
        assert_eq!(note, "copied 5 chars");
        assert!(*until > Instant::now(), "the note must not arrive expired");

        // A plain click copies nothing, so it must not claim to have.
        app.flash = None;
        press(&mut app, 2, 0);
        release(&mut app, 2, 0);
        assert!(app.flash.is_none(), "a click is not a copy");
    }

    /// One character is not "1 chars".
    #[test]
    fn the_note_counts_in_characters_not_bytes() {
        let mut app = App::new("t".into());
        app.body_origin = (0, 0);
        app.viewport = (40, 4);
        // Three characters, six bytes of UTF-8: the count must follow the
        // characters, or a selection of accented text reports twice its size.
        app.push(entry("éàê"));
        app.rows = visible_rows(&app.history, 40, 4, 0);

        press(&mut app, 0, 0);
        drag(&mut app, 3, 0);
        release(&mut app, 3, 0);
        assert_eq!(app.flash.as_ref().unwrap().0, "copied 3 chars");

        app.flash = None;
        press(&mut app, 0, 0);
        drag(&mut app, 1, 0);
        release(&mut app, 1, 0);
        assert_eq!(app.flash.as_ref().unwrap().0, "copied 1 char");
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
        // Five rows in total: the long entry's four (offsets 0/10/20/30), then
        // "short". Each step back moves the two-row window up by exactly one.
        for (back, expect) in [
            (0, [(0, 30), (1, 0)]),
            (1, [(0, 20), (0, 30)]),
            (2, [(0, 10), (0, 20)]),
            (3, [(0, 0), (0, 10)]),
        ] {
            let got: Vec<(usize, usize)> = visible_rows(&app.history, 10, 2, back)
                .iter()
                .map(|r| (r.entry, r.offset))
                .collect();
            assert_eq!(got, expect, "scroll_back {back}");
        }
    }
}
