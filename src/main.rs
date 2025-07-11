mod arp_spoof;
mod dhcp_spoof;
mod dns_spoof;
mod mac;
mod mode;
mod portscan;

use colored::Colorize;
use mode::select_mode;
use pnet::datalink::{self};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::process::Command;

fn get_interface_input() -> String {
    println!("{}", "Available interfaces:".green().bold());
    for iface in datalink::interfaces() {
        println!("{}", iface.name.red().bold());
    }
    print!("Interface: ");
    io::stdout().flush().unwrap();
    let mut iface = String::new();
    io::stdin().read_line(&mut iface).unwrap();
    iface.trim().to_string()
}

fn ip_input(prompt: &str) -> Ipv4Addr {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let mut ip = String::new();
    io::stdin().read_line(&mut ip).unwrap();
    ip.trim().parse().unwrap()
}

fn main() {
    let selected_mode = select_mode();
    println!(
        r#"
                                ]11111111111[
                           !+0hhhhkhkkhkhhhkkhhO+i
                        "XhhhhhkhdZOZZOOOOZphhhhhhhU:'
                      :XhhhkhkC:             :0khhhhhhn.
                    "rdhkhk}}".                 ."]hhahhd|
                   [mhhhz_^                       .;fhhhhm]
                 ~Lkhkp1`                            Ivahaq[
                !zhhhJ>                               lXaaha)
               Ichhhx,                                  (aaaa1
              ^/hkh/       .:ll:.           .llll:       |aaaa}}
              ]hkhq{{     .XaaahaaI         ;aaaoooU.      taaa1.
             !Uhhht      vhaaoaaaai.     'uaaooooooY      toooa}}
             ?hhh0?     xkaoaoaoaaa"     ^aaaoooo*ohx      fooo[
             ]hhhj      <Qaoaaoaaa|'     'uhhaaooooC;      joo*[
             ?hhaj       ]mooooaan^       `xhaooooq[       jo*of"
             ]aaaj         /XXX]`           ']zXf          j*o*Yl
             ]aaar                                         j**oC!
             ]aaor                  'lmt'.                 j****]
             ?aaor                 JmZZZZJ.                j*o*o[
             ]aaoj                LZZ000Q0J                j****]
             ]aaor                COZQQQQQU                jo*o*]
             ]hhhj                 fQCLCC[                 foooo[
             ?khkj                   )|>                   faaaa?
             ?kkkf                                         tkhhd-
             -dpdt                  ''''''                 tkkkcl
             -qqq/                  tjjjft                 |pppvI
             +ZZO(                 zZmZZmQ                 (mmwnI
             +QQL)                 Zdddddw                 1Q0OU>
            .~JCC{{          +uX+'  ~+~+}}]; .>fn-:         {{QQQQ+
            "{{YYY}}         .tXzz,  <++~}}[; "zXzz/         [YUUU<
            !vvvx+         `tczc:  <+++}}[I "cccc|          }}zzz?`
           !uvvu[          >rzcc,  ~~+~}}[> "uccc|          Itccc<.
          Irxxx[           >jvvc,  ~+++}}[< `[vvv(           .}}uuuxI
 !(|}}[?]1)fjjrr/>          )uuuu,  <~+~}}[l '[uuu/;          _jxxxxx/(}}((jr(.
 I)(((|//tttfffjt-"      ,)nnnuu,  <+++}}}}- "nunnnj~      .!|rrjrjrjrjjjjjji
  i1)(|(/|1l ,[fjjj1___-|xnnnnnnx" <~+~}}[-'[nnnnxxxj1__+{{fjrjf]~+(jjfffft~.
      ^`      :}}ffjjjrrxxxx1?[jnnu{{++++}}}}nnnxf]1xxrrrjjjjjj{{;     >_-,
                 l{{(fjj|1-"   ?jxxx++~+}}[}}{{xxj]   :}}1/jfj|{{<'
                                {{fr_++~}}}}f1
                                  .l~++}}}}]
                                   :~+~}}}}]
                                   :~++}}[]
                                   ,~+~}}}}]
                                   "~++}}}}]
                                   ^<<<?-?+
                                    "llll;
                                     ;lIl
                                      Il

                                  ^^^^^^^^^^^
                                This is Ghostyyyyy!
                                Funfact: He likes to draw :))
    "#
    );
    let warnings = [
        "THIS TOOL IS ONLY FOR PENETRATION TESTING AND NOT FOR ILLEGAL PURPOSES",
        "ABUSE IS GOING TO BE PUNISHED!!! IDK BY WHO...",
    ];

    println!("You have selected {}.", selected_mode.green().bold());

    println!(
        "{}",
        "------------------------\n=======next step:=======\n------------------------\n"
            .yellow()
            .bold()
    );
    for warning in warnings.iter() {
        println!("{}", warning.red().bold());
    }
    match selected_mode {
        "Port Scan" => {
            println!("Scan IP:");
            let mut ip = String::new();
            io::stdin().read_line(&mut ip).expect("Failed to read line");
            portscan::scan(ip.trim().parse().unwrap());
        }
        "DNS Spoof(u have to disable automatic ip configuration and have to manually configure ur ip address and on windows idk how to do it)" => {
            if cfg!(any(target_os = "linux", target_os = "macos")) {
                if whoami::username().unwrap().to_string() != "root" {
                    println!("This operation requires root privileges. Re-running with sudo...");
                    Command::new("sudo")
                        .arg(std::env::current_exe().unwrap())
                        .args(std::env::args().skip(1))
                        .status()
                        .expect("failed to execute sudo");
                }
            }
            dns_spoof::main().expect("Codeh panicked");
            main()
        }
        "DHCP Spoof" => {

            if cfg!(any(target_os = "linux", target_os = "macos")) {
                if whoami::username().unwrap().to_string() != "root" {
                    println!("This operation requires root privileges. Re-running with sudo...");
                    Command::new("sudo")
                        .arg(std::env::current_exe().unwrap())
                        .args(std::env::args().skip(1))
                        .status()
                        .expect("failed to execute sudo");
                }
            }
            dhcp_spoof::main().expect("Codeh panicked");
        }
        "ARP Spoof(extremely overpowered in broadcast mode(then preforms a mitm attack to EVERYONE in the network))" => {
            if cfg!(any(target_os = "linux", target_os = "macos")) {
                if whoami::username().unwrap().to_string() != "root" {
                    println!("This operation requires root privileges. Re-running with sudo...");
                    Command::new("sudo")
                        .arg(std::env::current_exe().unwrap())
                        .args(std::env::args().skip(1))
                        .status()
                        .expect("failed to execute sudo");
                }
            }
            arp_spoof::main();

        }
        _ => {
            println!("Unknown mode selected");
        }
    }
}
