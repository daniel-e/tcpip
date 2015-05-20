#include <netdb.h>        // gethostbyname
#include <netinet/tcp.h>  // struct tcphdr
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>       // close
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <functional>
#include <pcap.h>
#include <iostream>
#include <thread>

#include "net.hh"

#define SIZE_ETHERNET    14
#define MAGIC 0xa387

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

struct icmp
{
	u_int8_t type;
	u_int8_t code;
	u_int16_t sum;
	u_int16_t id;
	u_int16_t seq;
};


u_int16_t send_msg(const char* dstip, const char* buf, unsigned size)
{
	u_int32_t ret    = (u_int32_t) -1;
	char*     packet = (char*) malloc(sizeof(struct icmp) + size);

	if (size > (1 << 14)) {
		perror("packet too large.");
		return ret;
	}

	if (!packet) {
		perror("malloc()");
		return ret;
	}

	u_int16_t seq = rand();

	// copy data into icmp packet
	memcpy(packet + sizeof(struct icmp), buf, size);

	struct icmp* i = (struct icmp*) packet;
	i->type = 8; // echo request
	i->code = 1;
	i->sum = 0;
	i->id = htons(MAGIC);
	i->seq = htons(seq);
	i->sum = chksum(packet, sizeof(struct icmp) + size);
	
	// open socket and send packet
	int sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sd < 0) {
		perror("socket() error");
		return ret;
	}

	struct sockaddr_in s;
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr(dstip);

	if (sendto(sd, packet, sizeof(struct icmp) + size, 0, (struct sockaddr*) &s, sizeof(s)) < 0) {
		perror("sendto() error");
		return ret;
	}
	close(sd);

	return seq;
}

std::string resolve_host(const std::string& host) 
{
	return inet_ntoa(*((struct in_addr*) gethostbyname(host.c_str())->h_addr));
}


pcap_t* setup_pcap(const char* dev, const char* filter)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, PCAP_ERRBUF_SIZE, 1, 1000, errbuf);
	if (!handle) {
		std::cerr << "Could not open device " << dev << " " << errbuf << std::endl;
		return 0;
	}

	struct bpf_program bpf;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	if (pcap_compile(handle, &bpf, filter, 0, net) == -1) {
		std::cerr << "Could not set filter" << std::endl;
		return 0;
	}

	if (pcap_setfilter(handle, &bpf) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
		return 0;
	}
	return handle;
}

void got_packet(u_char* args, const struct pcap_pkthdr* h, const u_char* packet)
{
	if (!h->len || h->len < SIZE_ETHERNET + 20) return;

	const u_char* p = packet;
	packet += SIZE_ETHERNET;

	u_int16_t iphdrlen = *packet & 0xf;       // little endian
	u_int8_t  proto    = *(packet + 9);       // protocol (should be 1)
	u_int16_t iplen    = ntohs(*(u_int16_t*)(packet + 2));

	if (iplen < iphdrlen * 4) return;
	if (proto != 1) return;
	if (h->len < SIZE_ETHERNET + iphdrlen * 4 + sizeof(icmp)) return;

	packet += iphdrlen * 4;
	struct icmp* i = (struct icmp*) packet;

	if (i->type != 0 && i->type != 8) return; // no ping, no poing
	if (ntohs(i->id) != MAGIC) return;

	int datalen = iplen - iphdrlen * 4 - sizeof(struct icmp);
	int type    = (i->type == 0 ? PONG : PING);
	packet += sizeof(struct icmp);

	if (iphdrlen * 4 + sizeof(struct icmp) > iplen) return;
	if (h->len < SIZE_ETHERNET + iphdrlen * 4 + sizeof(icmp) + datalen) return;

	void(*callback)(std::string, int) = (void (*)(std::string, int)) args;
	callback(std::string((const char*) packet, datalen), type);
}

void do_callback(pcap_t* handle, void(*callback)(std::string, int)) 
{
	pcap_loop(handle, -1, got_packet, (u_char*) callback);
	pcap_close(handle);
}

bool recv_callback(const char* dev, void(*callback)(std::string, int)) {

	pcap_t* handle = setup_pcap(dev, "icmp");
	if (handle) {
		new std::thread(do_callback, handle, callback);
	}
	return (handle != 0);
}

