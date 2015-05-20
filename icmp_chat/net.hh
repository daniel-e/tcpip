#ifndef NET_HH
#define NET_HH

#include <string>

enum {
	PING,
	PONG
};

u_int16_t   send_msg(const char* dstip, const char* buf, unsigned size);
std::string resolve_host(const std::string& host);
bool        recv_callback(const char* dev, void(*callback)(std::string, int type));

#endif
