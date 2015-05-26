//extern crate log;
extern crate time;
extern crate libc;

mod packet;

// TODO retry
// TODO ack
// TODO an additional layer to split larger messages into chunks
// TODO constant for maximum message size

use std::thread;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;

pub enum Errors {
	MessageTooBig,
	SendFailed
}


pub struct Message {
	pub ip : String,
	pub buf: Vec<u8>,
}

impl Message {
	pub fn new(ip: String, buf: Vec<u8>) -> Message {
		Message {
			ip : ip,
			buf: buf,
		}
	}
}


fn string_from_cstr(cstr: *const u8) -> String {

	let mut v: Vec<u8> = vec![];
	let mut i = 0;
	loop { unsafe {
		let c = *cstr.offset(i);
		if c == 0 { break; } else { v.push(c); }
		i += 1;
	} }
	String::from_utf8(v).unwrap()
}

struct SharedData {
	// Packets that have been transmitted and for which we
	// are waiting for the acknowledge.
	packets          : Vec<packet::Packet>,
	transmitted      : Vec<(packet::IdType, time::PreciseTime)>,
}
	

#[repr(C)]
pub struct Network {
	max_message_size : usize,
	callback_fn      : fn (Message),
	tx               : Sender<packet::IdType>,
	shared           : Arc<Mutex<SharedData>>
}

extern "C" fn callback(target: *mut Network, buf: *const u8, len: u32, typ: u32, srcip: *const u8) {

	if typ == 0 { // check only ping messages
		unsafe {
			(*target).recv_packet(buf, len, string_from_cstr(srcip));
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
	pub fn new(dev: String, cb: fn (Message)) -> Box<Network> {

		let (tx, rx) = channel();
		let s = Arc::new(Mutex::new(SharedData {
			packets : vec![],
			transmitted: vec![],
		}));
		
		let k = s.clone();

		// Network must be on the heap because of the callback function.
		let mut n = Box::new(Network {
			shared: s,
			max_message_size: (16 * 1024),  // 16k
			callback_fn: cb,
			tx: tx,
		});

		n.init_callback(dev);
		n.init_retry_event_receiver(rx, k);
		n
	}

	fn init_retry_event_receiver(&self, rx: Receiver<packet::IdType>, k: Arc<Mutex<SharedData>>) {
		thread::spawn(move || { loop { match rx.recv() {
			Ok(id) => {
				let shared = k.lock().unwrap();
				println!("got retry event for id {}", id);
			}
			_ => { println!("error in receiving"); }
		}}});
	}

	fn init_callback(&mut self, dev: String) {
		let sdev = dev.clone() + "\0";
		unsafe {
			recv_callback(&mut *self, sdev.as_ptr(), callback); // TODO error handling
		}
	}

	pub fn recv_packet(&self, buf: *const u8, len: u32, ip: String) {
		let r = packet::Packet::deserialize(buf, len);
		match r {
			Some(p) => {
				let mut ignore = false;
				let s = self.shared.clone();
				let k = s.lock().unwrap();
				for v in &k.packets { // TODO thread-safety
					println!("v.id = {}", v.id);
					if v.id == p.id {
						// we are the sender of the message because
						// the message is queued
						// ignore = true;
						// break;
					}
				}
				if ignore == false {
					let m = Message {
						ip: ip,
						buf: p.data.clone()
					};
					(self.callback_fn)(m);
				}
			},
			None => { println!("recv_packet: could not deserialize received packet"); }
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
			Err(Errors::MessageTooBig)
		} else {
			let p = packet::Packet::new(buf.clone(), ip.clone());

			// We push the message before we send the message in case that
			// the callback for ack is called before the message is in the
			// queue.
			let v = self.shared.clone();
			let mut k = v.lock().unwrap();
			k.packets.push(p.clone());

			if self.transmit(&p) {
				k.transmitted.push((p.id, time::PreciseTime::now()));
				self.init_retry(p.id);
				Ok(p.id) 
			} else {
				k.packets.pop();
				Err(Errors::SendFailed)
			}
		}
	}

	fn init_retry(&self, id: packet::IdType) {

		let tx = self.tx.clone();
		thread::spawn(move || { 
			thread::sleep_ms(300);
			match tx.send(id) {
				Err(_) => { println!("init_retry: sending event through channel failed"); }
				_ => { }
			}
		});
	}

	fn transmit(&self, p: &packet::Packet) -> bool {
	
		let v  = p.serialize();
		let ip = p.ip.clone() + "\0";
		unsafe {
			send_icmp(ip.as_ptr(), v.as_ptr(), v.len() as u16) == 0
		}
	}
}
