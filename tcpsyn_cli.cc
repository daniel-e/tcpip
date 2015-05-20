#include <netdb.h>  // gethostbyname
#include <cstdio>
#include <iostream>
#include <boost/program_options.hpp>

#include "tcp.hh"
#include "pseudo.hh"

namespace po = boost::program_options;

#define DEFAULT_PORT 54321

int         port;
std::string dsthost;
std::string srchost;

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
	tcp t(srchost.c_str(), dsthost.c_str());

	t.tcph.th_dport = htons(port);
	t.tcph.th_sport = htons(30000 + rand() % 20000);
	t.tcph.th_seq = htonl(data);
	t.tcph.th_ack = 0;
	t.tcph.th_off = 5; // size of tcp header in 32-bit words
	t.tcph.th_x2 = 0;
	t.tcph.th_flags = TH_SYN;
	t.tcph.th_win = htons(32767);
	t.tcph.th_urp = 0;
	t.update_chksum();

	if (sendto(sd, &t.tcph, sizeof(t.tcph), 0, (struct sockaddr*) &s, sizeof(s)) < 0) {
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

