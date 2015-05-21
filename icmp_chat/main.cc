#include <netdb.h>        // gethostbyname
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <iostream>
#include <boost/program_options.hpp>

#include "net.hh"

namespace po = boost::program_options;

void f(const char* buf, int len, int type)
{
	std::string s(buf, len);
	std::cout << s << "," << s.size() << "," << type << std::endl;
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

	char* ip = inet_ntoa(*((struct in_addr*) gethostbyname(dsthost.c_str())->h_addr));

	recv_callback("eth0", f);
	sleep(1);
	send_msg(ip, "hello", 5);
	sleep(2);
}

