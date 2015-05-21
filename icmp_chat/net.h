#ifndef NET_HH
#define NET_HH

enum {
	PING,
	PONG
};

u_int16_t   send_msg(const char* dstip, const char* buf, u_int16_t size);
// returns 0 on success
int         recv_callback(const char* dev, void(*callback)(const char* buf, int len, int type));

#endif
