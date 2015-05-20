#include <netinet/tcp.h>  // struct tcphdr
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>       // close
#include <string.h>
#include <iostream>

struct icmp
{
	u_int8_t type;
	u_int8_t code;
	u_int16_t sum;
	u_int16_t id;
	u_int16_t seq;
	char data[12];
};

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
	const char* srcip = "10.21.40.198";
	const char* dstip = "193.99.144.80";

	struct icmp i;

	i.type = 8; // echo request
	i.code = 1;
	i.sum = 0;
	i.id = htons(rand());
	i.seq = htons(rand());
	memcpy(&i.data, "Hello World!", 12);
	i.sum = chksum((const char*) &i, sizeof(struct icmp));
	
	// open socket and send packet
	int sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sd < 0) {
		perror("socket() error");
		return 1;
	}

	struct sockaddr_in s;
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr(dstip);

	if (sendto(sd, &i, sizeof(struct icmp), 0, (struct sockaddr*) &s, sizeof(s)) < 0) {
		perror("sendto() error");
		return 1;
	}
	close(sd);
}

