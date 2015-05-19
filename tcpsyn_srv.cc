#include <unistd.h> // close
#include <cstdio>
#include <iostream>

#include "tcp.hh"
#include "pseudo.hh"

#define DSTPORT 54321
#define DSTHOST "127.0.0.1"
#define SRCHOST "127.0.0.1"

int sd;
struct sockaddr_in s;

void send_data(u_int32_t data) 
{
	// create the packet
	tcp t(SRCHOST, DSTHOST);

	t.tcph.th_dport = htons(DSTPORT);
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
		return;
	}
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

int main()
{
	srand(time(0));

	// open socket and send packet
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sd < 0) {
		perror("socket() error");
		return 1;
	}
	s.sin_family = AF_INET;
	s.sin_port = htons(DSTPORT);
	s.sin_addr.s_addr = inet_addr(DSTHOST);

	// read from stdin and send data via SYN packets
	std::string s;
	while (std::getline(std::cin, s)) {
		send_msg(s + "\n");
	}

	close(sd);
}

