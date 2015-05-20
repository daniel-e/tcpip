#include <netinet/tcp.h>  // struct tcphdr
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>       // close
#include <time.h>
#include <iostream>

// usage:
// 1) tcpdump -i lo "port 8080"
// 2) sudo ./syn_tcp

// man 7 raw, man 7 packet, man 7 socket

typedef struct
{
	// pseudo header
	in_addr_t src;
	in_addr_t dst;
	u_int8_t  zero = 0;
	u_int8_t  protocol = 6;    // tcp
	u_int16_t len;

	// tcp header
	tcphdr tcph;
} pseudo_and_tcp;

// http://tools.ietf.org/html/rfc793
// http://tools.ietf.org/html/rfc1071
// http://locklessinc.com/articles/tcp_checksum/
u_int16_t chksum(const char* buffer, int size)
{
	u_int32_t sum = 0;
	for (int i = 0; i < size - 1; i += 2) {
		sum += *(unsigned short*) &buffer[i];
	}
	if (size & 1) sum += (unsigned) (unsigned char) buffer[size - 1];
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

int main() 
{
	srand(time(0));

	const char* srcip = "127.0.0.1";
	const char* dstip = "127.0.0.1";
	int dstport = 8080;
	int srcport = 30000 + rand() % 20000;

	// create the packet
	pseudo_and_tcp pt;
	pt.src = inet_addr(srcip);
	pt.dst = inet_addr(dstip);
	pt.len = htons(sizeof(tcphdr));

	pt.tcph.th_dport = htons(dstport);
	pt.tcph.th_sport = htons(srcport);
	pt.tcph.th_seq = htonl(rand());
	pt.tcph.th_ack = 0;
	pt.tcph.th_off = 5; // size of tcp header in 32-bit words
	pt.tcph.th_x2 = 0;
	pt.tcph.th_flags = TH_SYN;
	pt.tcph.th_win = htons(32767);
	pt.tcph.th_sum = 0;
	pt.tcph.th_urp = 0;

	pt.tcph.th_sum = chksum((const char*) &pt, sizeof(pseudo_and_tcp));

	// open socket and send packet
	int sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sd < 0) {
		perror("socket() error");
		return 1;
	}

	struct sockaddr_in s;
	s.sin_family = AF_INET;
	s.sin_port = pt.tcph.th_dport;
	s.sin_addr.s_addr = inet_addr(dstip);

	if (sendto(sd, &pt.tcph, sizeof(pt.tcph), 0, (struct sockaddr*) &s, sizeof(s)) < 0) {
		perror("sendto() error");
		return 1;
	}
	close(sd);
}

