#ifndef NET_HH
#define NET_HH

enum {
	PING,
	PONG
};

// returns 0 on success
int         send_icmp(const char* dstip, const char* buf, u_int16_t size);
// returns 0 on success
int         recv_callback(void* target, const char* dev, void(*callback)(void*, const char* buf, u_int32_t len, u_int32_t type, const char* srcip));

#endif
