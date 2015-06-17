#include <netinet/tcp.h>  // struct tcphdr
#include <netdb.h>        // gethostbyname
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>       // close
#include <string.h>
#include <iostream>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

struct udp
{
	u_int16_t srcport;
	u_int16_t dstport;
	u_int16_t len;
	u_int16_t chk;
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

int main(int ac, char** av) 
{
	std::string dsthost = "127.0.0.1";

	// parse options
	po::options_description desc("Options");
	desc.add_options()
		("help,h", "this help message")
		("dst,d", po::value<std::string>(&dsthost)->default_value("127.0.0.1"), "destination host/ip")
	;
	po::variables_map vm;
	po::store(po::parse_command_line(ac, av, desc), vm);
	po::notify(vm);

	if (vm.count("help")) {
		std::cerr << desc << std::endl;
		return 1;
	}

	dsthost = inet_ntoa(*((struct in_addr*) gethostbyname(dsthost.c_str())->h_addr));

	const char* msg = 
		"<30>1 2015-06-17T09:14:16Z hostname binname 3938 "
		"- - This is a syslog message.";

	int len = sizeof(udp) + strlen(msg);
	char buf[4096];

	struct udp* udp_packet = (struct udp*) buf;

	udp_packet->srcport = htons(12345);
	udp_packet->dstport = htons(514);
	udp_packet->len = htons(len);
	udp_packet->chk = 0;

	memcpy(buf + sizeof(udp), msg, strlen(msg));

	// open socket and send packet
	int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sd < 0) {
		perror("socket() error");
		return 1;
	}

	struct sockaddr_in s;
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr(dsthost.c_str());

	if (sendto(sd, buf, len, 0, (struct sockaddr*) &s, sizeof(s)) < 0) {
		perror("sendto() error");
		return 1;
	}
	close(sd);
}

