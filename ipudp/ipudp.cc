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

struct ip
{
	u_int8_t ihl: 4;
	u_int8_t version: 4;
	u_int8_t tos;
	u_int16_t len;
	u_int16_t id;
	u_int16_t fragment_off;
	u_int8_t ttl;
	u_int8_t proto;
	u_int16_t chk;
	u_int32_t srcip;
	u_int32_t dstip;
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

	const char* udp_payload = 
		"<30>1 2015-06-17T09:14:16Z hostname binname 7324 "
		"- - This is a syslog message.";

	int  len = 0;
	char buf[4096];

	struct ip* ip_msg = (struct ip*) (buf + len);

	ip_msg->version = 4;
	ip_msg->ihl = 5;
	ip_msg->tos = 0;
	ip_msg->len = 0; // will be updated later
	ip_msg->id = rand();
	ip_msg->fragment_off = 0;
	ip_msg->ttl = 64;
	ip_msg->proto = 17; // udp
	ip_msg->chk = 0;
	ip_msg->srcip = inet_addr("2.2.2.2"); // faked source IP address
	ip_msg->dstip = inet_addr(dsthost.c_str());
	len += sizeof(ip);

	// ----

	struct udp* udp_packet = (struct udp*) (buf + len);

	udp_packet->srcport = htons(12345);
	udp_packet->dstport = htons(514);
	udp_packet->len = htons(sizeof(udp) + strlen(udp_payload));
	udp_packet->chk = 0;
	len += sizeof(udp);

	memcpy(buf + len, udp_payload, strlen(udp_payload));
	len += strlen(udp_payload);

	// open socket and send packet
	int sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sd < 0) {
		perror("socket() error");
		return 1;
	}

	ip_msg->len = len;
	ip_msg->chk = chksum(buf, sizeof(ip));

	int one = 1;
	const int *val = &one;
	if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
		printf ("setsockopt() failed");
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

