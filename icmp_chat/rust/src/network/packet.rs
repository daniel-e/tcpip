extern crate rand;

pub struct Packet {
	// The id of the packet that is transmitted. It is used to identify
	// the ack for that message.
	pub id : u64,
	ip     : String,       // IP of the receiver.
	data   : Vec<u8>,      // data packet from the caller
}

impl Packet {
	// ip = IP of the receiver
	// data = message
	pub fn new(ip: String, data: Vec<u8>) -> Packet {
		let r = rand::random::<u64>();
		Packet { 
			ip: ip, 
			data: data, 
			id: r,
		}
	}
}
