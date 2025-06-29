use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode};
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Margin;
use ratatui::prelude::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Terminal;
use std::time::Duration;
use ratatui::style::Stylize;

pub(crate) fn select_mode() -> &'static str {
    let modes = vec![
        "ARP Spoof(extremely overpowered in broadcast mode)",
        "DNS Spoof",
        "DHCP Spoof",
        "Port Scan",
    ];
    let mut selected_index = 0;
    let mut list_state = ratatui::widgets::ListState::default();
    list_state.select(Some(selected_index));

    crossterm::terminal::enable_raw_mode().unwrap();
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen, EnableMouseCapture).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    let selected_mode;
    loop {
        terminal
            .draw(|f| {
                let size = f.area();
                let block = Block::default()
                    .title("Welcome to GhostPen, your pentesting toolkit written in rust.")
                    .fg(Color::Red)
                    .borders(Borders::ALL);
                f.render_widget(block, size);
                let list_items: Vec<ListItem> = modes
                    .iter()
                    .enumerate()
                    .map(|(i, mode)| {
                        let content = if i == selected_index {
                            format!("> {}", mode)
                        } else {
                            format!("  {}", mode)
                        };
                        let style = if i == selected_index {
                            Style::default()
                                .fg(Color::Green)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Red)
                        };
                        ListItem::new(content).style(style)
                    })
                    .collect();

                let list = List::new(list_items).block(
                    Block::default()
                        .title("Available Modes")
                        .borders(Borders::NONE),
                );
                let area = size.inner(Margin {
                    vertical: 1,
                    horizontal: 1,
                });
                f.render_stateful_widget(list, area, &mut list_state);
            })
            .unwrap();

        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                match key.code {
                    KeyCode::Up => {
                        if selected_index > 0 {
                            selected_index -= 1;
                            list_state.select(Some(selected_index));
                        }
                    }
                    KeyCode::Down => {
                        if selected_index < modes.len() - 1 {
                            selected_index += 1;
                            list_state.select(Some(selected_index));
                        }
                    }

                    KeyCode::Enter => {
                        crossterm::terminal::disable_raw_mode().unwrap();
                        crossterm::execute!(
                            terminal.backend_mut(),
                            LeaveAlternateScreen,
                            DisableMouseCapture
                        )
                        .unwrap();
                        terminal.show_cursor().unwrap();
                        selected_mode = modes[selected_index];
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    selected_mode
}
