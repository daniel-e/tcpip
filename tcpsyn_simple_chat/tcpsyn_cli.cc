#include <netinet/tcp.h>  // struct tcphdr
#include <netdb.h>        // gethostbyname
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdio>
#include <iostream>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

#define DEFAULT_PORT 54321

int         port;
std::string dsthost;
std::string srchost;

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

void send_data(u_int32_t data) 
{
	int sd;
	struct sockaddr_in s;

	// open socket and send packet
	if ((sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		perror("socket() error");
		return;
	}

	s.sin_family = AF_INET;
	s.sin_port = htons(port);
	s.sin_addr.s_addr = inet_addr(dsthost.c_str());

	// create the packet
	pseudo_and_tcp pt;
	pt.src = inet_addr(srchost.c_str());
	pt.dst = inet_addr(dsthost.c_str());
	pt.len = htons(sizeof(tcphdr));

	pt.tcph.th_dport = htons(port);
	pt.tcph.th_sport = htons(30000 + rand() % 20000);
	pt.tcph.th_seq = htonl(data);
	pt.tcph.th_ack = 0;
	pt.tcph.th_off = 5; // size of tcp header in 32-bit words
	pt.tcph.th_x2 = 0;
	pt.tcph.th_flags = TH_SYN;
	pt.tcph.th_win = htons(32767);
	pt.tcph.th_sum = 0;
	pt.tcph.th_urp = 0;

	pt.tcph.th_sum = chksum((const char*) &pt, sizeof(pseudo_and_tcp));
	
	if (sendto(sd, &pt.tcph, sizeof(pt.tcph), 0, (struct sockaddr*) &s, sizeof(s)) < 0) {
		perror("sendto() error");
	}

	close(sd);
}

void send_msg(const std::string& s)
{
	for (unsigned i = 0; i < s.size();) {
		u_int32_t x = 0;
		for (unsigned j = 0; j < 4 && i < s.size(); ++j, ++i) {
			x = (x << 8) | s[i];
		}
		send_data(x);
	}
}

int main(int ac, char** av)
{
	srand(time(0));

	// parse options
	po::options_description desc("Options");
	desc.add_options()
		("help,h", "this help message")
		("dst,d", po::value<std::string>(&dsthost)->default_value("127.0.0.1"), "destination host/ip")
		("src,s", po::value<std::string>(&srchost)->default_value("127.0.0.1"), "source host/ip")
		("port,p", po::value<int>(&port)->default_value(DEFAULT_PORT), "destination port")
	;
	po::variables_map vm;
	po::store(po::parse_command_line(ac, av, desc), vm);
	po::notify(vm);

	if (vm.count("help")) {
		std::cerr << desc << std::endl;
		return 1;
	}

	dsthost = inet_ntoa(*((struct in_addr*) gethostbyname(dsthost.c_str())->h_addr));
	srchost = inet_ntoa(*((struct in_addr*) gethostbyname(srchost.c_str())->h_addr));

	std::cout << srchost << " -> " << dsthost << ":" << port << std::endl;

	// read from stdin and send data via SYN packets
	std::string s;
	while (std::getline(std::cin, s)) {
		send_msg(s + "\n");
	}
}

