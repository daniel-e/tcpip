extern crate rand;
extern crate time;

pub struct Packet {
	// The id of the packet that is transmitted. It is used to identify
	// the ack for that message.
	pub id:      u64,
	pub data:    Vec<u8>,      // data packet from the caller
	pub created: time::PreciseTime,
	pub ip:      String,
}

impl Packet {
	// data = message
	pub fn new(data: Vec<u8>, ip: String) -> Packet {
		let r = rand::random::<u64>();
		Packet { 
			data: data, 
			id: r,
			created: time::PreciseTime::now(),
			ip: ip,
		}
	}

	pub fn serialize(&self) -> Vec<u8> {

		// version + type
		let mut v: Vec<u8> = vec![1, 16]; 
		// id
		let mut t = self.id;
		for _ in 0..8 {
			v.push(t as u8);
			t = t >> 8;
		}
		// data / payload
		for k in self.data.clone() {
			v.push(k);
		}
		v
	}

	pub fn deserialize(buf: *const u8, len: u32) -> Option<Packet> {

		if len < 10 {
			return None;
		}

		let mut raw = Packet{ 
			id: 0, 
			data: vec![], 
			created: time::PreciseTime::now(),
			ip: "0.0.0.0".to_string()
		};

		unsafe {
			let ver : u8 = *buf.offset(0);
			let typ : u8 = *buf.offset(1);

			if ver != 1 || typ != 16 {
				return None;
			}
			for i in 0..8 {
				raw.id = (raw.id << 8) + (*buf.offset(2 + 7 - i) as u64);
			}
			for i in 10..len {
				raw.data.push(*buf.offset(i as isize));
			}
			Some(raw)
		}
	}
}
