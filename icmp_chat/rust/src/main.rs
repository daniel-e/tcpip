use std::thread;

mod network;

fn main() {
	let mut n = network::Network::new("eth0");

	let dstip = "193.99.144.80";
	let data  = "hello world".to_string().into_bytes();
	let msg   = network::Message::new(dstip, data);

	thread::sleep_ms(1000);
	let r = n.send_msg(msg);
	match r {
		Ok(id) => { println!("message sent {}", id); }
		Err(e) => { println!("error"); }
	}
	
	thread::sleep_ms(2000);
}
