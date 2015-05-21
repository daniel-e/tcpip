#ifndef NET_HH
#define NET_HH

enum {
	PING,
	PONG
};

u_int16_t   send_msg(const char* dstip, const char* buf, unsigned size);
bool        recv_callback(const char* dev, void(*callback)(const char* buf, int len, int type));

#endif
