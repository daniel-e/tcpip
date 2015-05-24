mod packet; // TODO

extern crate libc;

pub enum Errors {
	MessageTooBig,
	SendFailed
}


pub struct Message {
	pub ip : String,
	pub buf: Vec<u8>,
}

impl Message {
	pub fn new(ip: &str, buf: Vec<u8>) -> Message {
		Message {
			ip : ip.to_string(),
			buf: buf,
		}
	}
}


fn string_from_cstr(cstr: *const u8) -> String {

	let mut v : Vec<u8> = vec![];
	let mut i = 0;
	loop { unsafe {
		let c = *cstr.offset(i);
		if c == 0 { break; } else { v.push(c); }
		i += 1;
	} }
	String::from_utf8(v).unwrap()
}


#[repr(C)]
pub struct Network {
	max_message_size : usize,
	// Packets that have been transmitted and for which we
	// are waiting for the acknowledge.
	packets          : Vec<packet::Packet>,
	callback_fn      : fn (Message)
}

extern "C" fn callback(target: *mut Network, buf: *const u8, len: u32, typ: u32, srcip: *const u8) {

	if typ == 0 { // check only ping messages
		unsafe {
			(*target).recv(buf, len, string_from_cstr(srcip));
		}
	}
}

#[link(name = "pcap")]
extern {
	fn send_icmp(ip: *const u8, buf: *const u8, siz: u16) -> libc::c_int;
	fn recv_callback(target: *mut Network, 
		dev: *const u8, 
		cb: extern fn(*mut Network, *const u8, u32, u32, *const u8)) -> libc::c_int;
}

impl Network {
	/// Constructs a new `Network`.
	pub fn new(dev: &str, cb: fn (Message)) -> Box<Network> {
		let mut n = Box::new(Network { 
			packets: vec![], 
			max_message_size: (16 * 1024),  // 16k
			callback_fn: cb,
			// TODO: an additional layer to split larger messages into chunks
		});
		let sdev = dev.to_string() + "\0";
		unsafe {
			recv_callback(&mut *n, sdev.as_ptr(), callback); // TODO error handling
		}
		n
	}

	pub fn recv(&mut self, buf: *const u8, len: u32, ip: String) {
		let r = packet::Packet::deserialize(buf, len);
		match r {
			Some(p) => {
				let mut ignore = false;
				for v in &self.packets { // TODO thread-safety
					println!("v.id = {}", v.id);
					if v.id == p.id {
						// we are the sender of the message because
						// the message is queued
						// ignore = true;
						// break;
					}
				}
				if ignore == false {
					println!("got new packet");
					let m = Message {
						ip: ip,
						buf: p.data.clone()
					};
					(self.callback_fn)(m);
				}
			},
			None => {}
		}
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
	pub fn send_msg(&mut self, msg: Message) -> Result<u64, Errors> {

		let ip  = msg.ip.clone();
		let buf = msg.buf.clone();

		if buf.len() > self.max_message_size {
			return Err(Errors::MessageTooBig);
		}

		let p          = packet::Packet::new(buf.clone(), ip.clone());
		let id         = p.id;
		let v          = p.serialize();
		let s : String = ip + "\0";

		// We push the message before we send the message in case that
		// the callback for ack is called before the message is in the
		// queue.
		self.packets.push(p); // TODO: thread-safety

		//let v = serialize(buf.clone(), id);
		unsafe {
			if send_icmp(s.as_ptr(), v.as_ptr(), v.len() as u16) != 0 { // error
				self.packets.pop(); // TODO: thread-safety
				return Err(Errors::SendFailed);
			}
		}
		Ok(id)
	}


	// TODO: retry
}


