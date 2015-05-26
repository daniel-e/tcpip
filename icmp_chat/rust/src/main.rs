mod network;

extern crate getopts;

use std::env;
use std::io;
use getopts::Options;

use network::Message;
use network::Network;

fn parse_arguments() -> Option<(String, String)> {

	// parse comand line options
	let args : Vec<String> = env::args().collect();

	let mut opts = Options::new();
	opts.optopt("i", "dev", "set the device where to listen for messages", "device");
	opts.optopt("d", "dst", "set the IP where messages are sent to", "IP");
	opts.optflag("h", "help", "print this message");

	let matches = match opts.parse(&args[1..]) {
		Ok(m) => { m }
		Err(f) => { panic!(f.to_string()) }
	};

	if matches.opt_present("h") {
		let brief = format!("Usage: {} [options]", args[0]);
		println!("{}", opts.usage(&brief));
		None
	} else {		
		let device = matches.opt_str("i").unwrap_or("lo".to_string());
		let dstip = matches.opt_str("d").unwrap_or("127.0.0.1".to_string());
		Some((device, dstip))
	}
}

fn callback(msg: Message) {

	let ip  = msg.ip;
	let buf = String::from_utf8(msg.buf).unwrap();

	println!("{} says: <{}>", ip, buf);
}

fn main() {

	let r = parse_arguments();
	if r.is_none() {
		return;
	}
	let (device, dstip) = r.unwrap();


	let mut n = Network::new(device.clone(), callback);

	println!("Device is        : {}", device);
	println!("Destination IP is: {}", dstip);
	println!("\nYou can now start writing ...");

	let mut s = String::new();
	while io::stdin().read_line(& mut s).unwrap() != 0 {
		let msg = Message::new(dstip.clone(), s.trim().to_string().into_bytes());
		match n.send_msg(msg) {
			Ok(id) => {
				println!("* transmitting... (id = {})", id);
			}
			Err(e) => { match e {
				network::Errors::MessageTooBig => { println!("main: message too big"); }
				network::Errors::SendFailed => { println!("main: sending failed"); }
			}}
		}
		s.clear();
	}
}
