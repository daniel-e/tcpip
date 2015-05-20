#include <iostream>
#include <boost/program_options.hpp>

#include "net.hh"

namespace po = boost::program_options;

void f(std::string s, int type)
{
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

	recv_callback("eth0", f);
	sleep(1);
	send_msg(resolve_host(dsthost).c_str(), "hello", 5);
	sleep(2);
}

