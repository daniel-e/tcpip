#ifndef TCP_HH
#define TCP_HH

#include <netinet/tcp.h>  // struct tcphdr
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>       // memcpy

#include "pseudo.hh"

class tcp
{
public:
	pseudo psdh; // pseudo tcp header followed by ...
	tcphdr tcph; // tcp header

	tcp(const char* src, const char* dst) : psdh(src, dst) 
	{ memset(&tcph, 0, sizeof(tcphdr)); }

	void update_chksum()
	{ tcph.th_sum = 0;
	  tcph.th_sum = psdh.chksum((const char*) &psdh, sizeof(pseudo) + sizeof(tcphdr)); }
};

#endif
