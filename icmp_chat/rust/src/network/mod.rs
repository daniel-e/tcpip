mod packet;

#[link(name = "pcap")]
extern {
	fn send_icmp(ip: *const u8, buf: *const u8, siz: u16) -> u16;
	fn recv_callback(target: *mut Network, dev: *const u8, cb: extern fn(*mut Network, *const u8, u32, u32));
}

enum ErrorType {
	MessageTooBig,
	SendFailed
}


pub struct Message {
	ip : String,
	buf: Vec<u8>,
}

impl Message {
	pub fn new(ip: &str, buf: Vec<u8>) -> Message {
		Message {
			ip : ip.to_string(),
			buf: buf,
		}
	}
}

extern "C" fn callback(target: *mut Network, buf: *const u8, len: u32, typ: u32) {

	if typ == 0 { // check only ping messages
		unsafe {
			(*target).callback(buf, len);
		}
	}
}

struct RawPacket {
	version: u8,
	typ: u8,
	id: u64,
	payload: Vec<u8>
}

fn serialize(buf: Vec<u8>, id: u64) -> Vec<u8> {

	let mut v: Vec<u8> = vec![1, 16]; // version + type
	let mut t = id;                   // id
	for i in 0..8 {
		v.push(t as u8);
		t = t >> 8;
	}
	for k in buf {           // payload
		v.push(k);
	}
	v
}

fn deserialize(buf: *const u8, len: u32) -> RawPacket {
	let mut raw = RawPacket{
		version: 0,
		typ: 0,
		id: 0,
		payload: vec![]
	};
	if len >= 10 {
		unsafe {
			raw.version = *buf.offset(0);
			raw.typ = *buf.offset(1);
			for i in 0..8 {
				raw.id = (raw.id << 8) + (*buf.offset(2 + 7 - i) as u64);
			}
			for i in 10..len {
				raw.payload.push(*buf.offset(i as isize));
			}
		}
	}
	raw
}


pub struct Network {
	// Packets that have been transmitted and for which we
	// are waiting for the acknowledge.
	packets          : Vec<packet::Packet>,
	max_message_size : usize,
	dev              : String
}

impl Network {
	/// Constructs a new `Network`.
	pub fn new(dev: &str) -> Network {
		let mut n = Network { 
			packets: vec![], 
			max_message_size: (16 * 1024),  // 16k
			dev: dev.to_string(),
			// TODO: an additional layer to split larger messages
		};
		n.init();
		n
	}

	pub fn init(&mut self) { // TODO: remove pub
		let sdev = self.dev.clone() + "\0";
		unsafe {
			recv_callback(&mut *self, sdev.as_ptr(), callback); // TODO error, eth0
		}
	}

	pub fn callback(&mut self, buf: *const u8, len: u32) {
		println!("recv {}", len);
		let raw = deserialize(buf, len);
		println!("x {}, typ {}, id {}", raw.version, raw.typ, raw.id);
		let s = String::from_utf8(raw.payload);
		println!("{}", s.unwrap());
		// TODO parse message
	}

	/// message format:
	/// u8 : version { 1 }
	/// u8 : type    { 16 = send message, 17 = ack }
	/// u64: id
	/// Vec<u8> : payload (msg) from layer above  (if type == 1)

	/// Sends a message to the receiver ip.
	///
	/// The message is send via an ICMP echo request and the function
	/// returns to the caller a handle which can be used by the caller
	/// to identify the message. The message is now in the status
	/// `transmitting`. As soon as an acknowledge is received the 
	/// configured callback function is called with the handle.
	///
	/// ip  = IPv4 of the receiver
	/// buf = data to be transmitted to the receiver
	pub fn send_msg(&mut self, msg: Message) -> Result<u64, ErrorType> {

		let ip  = msg.ip.clone();
		let buf = msg.buf.clone();

		if buf.len() > self.max_message_size {
			return Err(ErrorType::MessageTooBig);
		}

		let s : String = ip + "\0";
		let p          = packet::Packet::new(s.clone(), buf.clone());
		let id         = p.id;

		// We push the message before we send the message in case that
		// the callback for ack is called before the message is in the
		// queue.
		self.packets.push(p); // TODO: thread-safety

		let v = serialize(buf.clone(), id);
		unsafe {
			if send_icmp(s.as_ptr(), v.as_ptr(), v.len() as u16) != 0 { // error
				self.packets.pop(); // TODO: thread-safety
				return Err(ErrorType::SendFailed);
			}
		}
		Ok(id)
	}


	// TODO: retry
}


