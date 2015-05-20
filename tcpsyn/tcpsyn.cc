#include <time.h>
#include <unistd.h>  // close
#include <iostream>

#include "../pseudo.hh"
#include "../tcp.hh"

// usage:
// 1) nc -l 8080
// 2) start wireshark; filter: tcp.port == 8080
// 3) sudo ./syn_tcp

// man 7 raw, man 7 packet, man 7 socket

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

