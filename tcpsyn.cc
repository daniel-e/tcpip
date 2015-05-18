#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>  // struct tcphdr
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <iostream>

// usage:
// 1) nc -l 8080
// 2) start wireshark; filter: tcp.port == 8080
// 3) sudo ./syn_tcp

// man 7 raw, man 7 packet, man 7 socket

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

class tcp
{
public:
	pseudo psdh; // pseudo tcp header followed by ...
	tcphdr tcph; // tcp header

	tcp(const char* src, const char* dst) : psdh(src, dst) 
	{ memset(&tcph, 0, sizeof(tcphdr)); }

	void update_chksum()
	{ tcph.th_sum = psdh.chksum((const char*) &psdh, sizeof(pseudo) + sizeof(tcphdr)); }
};

int main() 
{
	srand(time(0));

	const char* srcip = "127.0.0.1";
	const char* dstip = "127.0.0.1";
	int dstport = 8080;
	int srcport = 30000 + rand() % 20000;

	// create the packet
	tcp t(srcip, dstip);

	t.tcph.th_dport = htons(dstport);
	t.tcph.th_sport = htons(srcport);
	t.tcph.th_seq = htonl(rand());
	t.tcph.th_ack = 0;
	t.tcph.th_off = 5; // size of tcp header in 32-bit words
	t.tcph.th_x2 = 0;
	t.tcph.th_flags = TH_SYN;
	t.tcph.th_win = htons(32767);
	t.tcph.th_urp = 0;
	t.update_chksum();

	// open socket and send packet
	int sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sd < 0) {
		perror("socket() error");
		return 1;
	}

	struct sockaddr_in s;
	s.sin_family = AF_INET;
	s.sin_port = t.tcph.th_dport;
	s.sin_addr.s_addr = inet_addr(dstip);

	if (sendto(sd, &t.tcph, sizeof(t.tcph), 0, (struct sockaddr*) &s, sizeof(s)) < 0) {
		perror("sendto() error");
		return 1;
	}
	close(sd);
}

