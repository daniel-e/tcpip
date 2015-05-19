#include <netinet/tcp.h>  // struct tcphdr
#include <pcap.h>
#include <iostream>

#define LISTENPORT    "54321"
#define SIZE_ETHERNET 14
#define IP_SIZE       20

void got_packet(u_char* args, const struct pcap_pkthdr* h, const u_char* packet)
{
	const tcphdr* tcp = (tcphdr*)(packet + SIZE_ETHERNET + IP_SIZE);

	u_int32_t x = tcp->th_seq; // no ntohl
	for (; x; x = x >> 8) {
		char c = x & 0xff;
		std::cout << c;
	}
}

pcap_t* setup_pcap(const char* dev, const char* filter)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, PCAP_ERRBUF_SIZE, 1, 1000, errbuf);
	if (!handle) {
		std::cerr << "Could not open device " << dev << " " << errbuf << std::endl;
		exit(2);
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
		exit(1);
	}

	if (pcap_setfilter(handle, &bpf) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
		exit(2);
	}
	return handle;
}

int main()
{
	const char* dev = "lo";
	const char* filter = "tcp && port " LISTENPORT;

	pcap_t* handle = setup_pcap(dev, filter);

	std::cout << "listening..." << std::endl;
	pcap_loop(handle, -1, got_packet, 0);
	pcap_close(handle);
}

