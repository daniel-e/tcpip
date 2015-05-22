mod network;

use network::Message;
use std::thread;


fn callback(msg: Message) {

	let ip  = msg.ip;
	let buf = String::from_utf8(msg.buf).unwrap();

	println!("got message from ip = {}, buf = {}", ip, buf);
}

fn main() {
	let mut n = network::Network::new("lo", callback);

	// TODO: after calling init() the Network object must not be moved
	// to another memory location. Otherwise, the callback function
	// jumps to a wrong address.
	n.init();

	let dstip = "127.0.0.1";
	let data  = "hello world".to_string().into_bytes();
	let msg   = Message::new(dstip, data);

	// Sleep one second to wait for pcap to become ready to read from
	// the device. Maybe this is not necessary.
	thread::sleep_ms(1000);

	let r = n.send_msg(msg);
	match r {
		Ok(id) => { 
			// Now, the message is in status 'transmitted'.
			println!("message sent; message handle = {}", id); 
		}
		Err(e) => { println!("error"); }
	}
	
	// Wait to seconds for the response to arrive.
	thread::sleep_ms(2000);
}
