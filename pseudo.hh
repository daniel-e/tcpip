#ifndef PSEUDO_HH
#define PSEUDO_HH

#include <netinet/tcp.h>  // struct tcphdr
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// pseudo tcp header; required to compute the tcp checksum
class pseudo {
public:
	in_addr_t src;
	in_addr_t dst;
	u_int8_t  zero = 0;
	u_int8_t  protocol = 6;    // tcp
	u_int16_t len;

	pseudo(const char* src, const char* dst) :
	src(inet_addr(src)), dst(inet_addr(dst)), len(htons(sizeof(tcphdr))) { }

	// http://tools.ietf.org/html/rfc793
	// http://tools.ietf.org/html/rfc1071
	// http://locklessinc.com/articles/tcp_checksum/
	u_int16_t chksum(const char* buffer, int size) const
	{
		u_int32_t sum = 0;
		for (int i = 0; i < size - 1; i += 2) {
			sum += *(unsigned short*) &buffer[i];
		}
		if (size & 1) sum += (unsigned) (unsigned char) buffer[size - 1];
		while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
		return ~sum;
	}
};

#endif

