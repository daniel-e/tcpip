mod network;

use network::Message;
use network::Network;
use std::io;

fn callback(msg: Message) {

	let ip  = msg.ip;
	let buf = String::from_utf8(msg.buf).unwrap();

	println!("got message from ip = {}, buf = {}", ip, buf);
}

fn main() {
	let mut n = Network::new("lo", callback);

	let dstip = "127.0.0.1";

	println!("You can now start writing ...");

	let mut s = String::new();
	while io::stdin().read_line(& mut s).unwrap() != 0 {
		let msg = Message::new(dstip, s.trim().to_string().into_bytes());
		match n.send_msg(msg) {
			Ok(id) => {
				println!("main: message was sent, id = {}", id);
			}
			Err(e) => {
				match e {
					network::Errors::MessageTooBig => { println!("main: message too big"); }
					network::Errors::SendFailed => { println!("main: sending failed"); }
				}
			}
		}
		s.clear();
	}
}
