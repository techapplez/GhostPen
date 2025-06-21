use crossterm::style::Stylize;
use myrustscan::{
    input::{PortRange, ScanOrder},
    port_strategy::PortStrategy,
    scanner::Scanner,
};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

struct PortFinding {
    port: u16,
    service: Option<String>,
    vulnerability_score: u8,
    found_at: SystemTime,
}

fn port_risk_weight(port: u16) -> u8 {
    match port {
        22 | 3389 => 10,
        3306 | 5432 => 8,
        21 | 23 => 7,
        80 | 8080 => 4,
        443 => 2,
        _ => 1,
    }
}

fn calculate_decay_factor(found_at: SystemTime) -> f32 {
    let now = SystemTime::now();
    let age = now
        .duration_since(found_at)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        / 86400;
    let decay = 1.0 - (age as f32 / 60.0);
    decay.max(0.1)
}

fn score_ports(findings: &[PortFinding]) -> (u8, &'static str) {
    let mut total_risk = 0.0;
    for finding in findings {
        let weight = port_risk_weight(finding.port) as f32;
        let vuln = finding.vulnerability_score as f32;
        let decay = calculate_decay_factor(finding.found_at);
        total_risk += (weight + vuln) * decay;
    }
    let mut score = 100.0 - total_risk;
    if score < 0.0 {
        score = 0.0;
    }
    let rating = match score as u8 {
        0..=19 => "Critical risk: Immediate action required.",
        20..=49 => "High risk: Review and mitigate vulnerabilities.",
        50..=79 => "Medium risk: Monitor and improve security posture.",
        _ => "Low risk: Good security posture.",
    };
    (score as u8, rating)
}

fn list_critical_ports(findings: &[PortFinding]) -> String {
    let mut critical = Vec::new();
    for finding in findings {
        if port_risk_weight(finding.port) >= 8 {
            critical.push(finding.port.to_string());
        }
    }

    if critical.is_empty() {
        "No critical ports detected".into()
    } else {
        format!("Critical ports: {}", critical.join(", "))
    }
}

pub fn scan(ip: IpAddr) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let scanner = Scanner::new(
            &[ip],
            10,
            Duration::from_millis(3000),
            1,
            false,
            PortStrategy::pick(
                &Some(PortRange {
                    start: 1,
                    end: 65535,
                }),
                None,
                ScanOrder::Serial,
            ),
            false,
            vec![],
            false,
        );

        let scan_result = scanner.run().await;

        let now = SystemTime::now();
        let mut findings = Vec::new();
        for addr in scan_result.iter() {
            let port_num = addr.port();
            let service = match port_num {
                22 => Some("ssh".into()),
                80 => Some("http".into()),
                443 => Some("https".into()),
                3306 => Some("mysql".into()),
                3389 => Some("rdp".into()),
                8123 => Some("Home Assistant".into()),
                _ => None,
            };
            let vulnerability_score = match port_num {
                22 => 5,
                3306 => 7,
                3389 => 4,
                80 => 2,
                8123 => 1,
                _ => 0,
            };
            findings.push(PortFinding {
                port: port_num,
                service,
                vulnerability_score,
                found_at: now,
            });
        }

        let (score, rating) = score_ports(&findings);
        if score <= 50 {
            println!("Security Score: {}/100", score.to_string().green().bold());
        } else if score >= 50 && score <= 75 {
            println!("Security Score: {}/100", score.to_string().yellow().bold());
        } else {
            println!("Security Score: {}/100", score.to_string().red().bold());
        }
        println!("Assessment: {}", rating);
        println!("{}", list_critical_ports(&findings));
    });
}
