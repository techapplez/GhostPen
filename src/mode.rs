use std::io;
use std::time::Duration;
use colored::Colorize;
use crossterm::{event, execute};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use crossterm::terminal::EnterAlternateScreen;
use ratatui::layout::Margin;
use ratatui::prelude::{Modifier, Style};
use ratatui::Terminal;
use ratatui::widgets::{Block, Borders, List, ListItem};

pub(crate) fn select_mode() {
    println!("{}", "THIS TOOL IS ONLY FOR PENETRATION TESTING AND NOT FOR ILLEGAL PURPOSES".red().bold().underline());
    println!("{}", "ABUSE IS GOING TO BE PUNISHED!!! IDK BY WHO...".red().bold().underline());
    println!("{}", "Available modes:".green().bold());

    let modes = vec![
        "ARP Spoof",
        "DNS Spoof",
        "DHCP Spoof",
        "DoS Attack"
    ];
    let mut selected_index = 0;

    enable_raw_mode().unwrap();
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    loop {
        terminal.draw(|f| {
            let size = f.area();
            let block = Block::default()
                .title("etterscap - Select Mode")
                .borders(Borders::ALL);
            f.render_widget(block, size);

            let list_items: Vec<ListItem> = modes
                .iter()
                .enumerate()
                .map(|(i, mode)| {
                    let content = if i == selected_index {
                        format!("> {}", mode).green().bold().to_string()
                    } else {
                        format!("  {}", mode).red().bold().to_string()
                    };
                    ListItem::new(content)
                })
                .collect();

            let list = List::new(list_items)
                .block(Block::default().title("Available Modes").borders(Borders::NONE))
                .highlight_style(Style::default().add_modifier(Modifier::BOLD));

            f.render_widget(list, size.inner(Margin { vertical: 1, horizontal: 1 }));
        }).unwrap();

        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                match key.code {
                    KeyCode::Up => selected_index = selected_index.saturating_sub(1),
                    KeyCode::Down => selected_index = (selected_index + 1).min(modes.len() - 1),
                    KeyCode::Enter => {
                        disable_raw_mode().unwrap();
                        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture).unwrap();
                        terminal.show_cursor().unwrap();
                        println!("{}", format!("{} mode selected.", modes[selected_index]).green().bold());
                        return;
                    }
                    _ => {}
                }
            }
        }
    }
}