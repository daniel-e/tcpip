#include <stdlib.h>       // exit
#include <pcap.h>
#include <iostream>
#include <boost/program_options.hpp>
#include <sstream>

#define DEFAULT_PORT  54321
#define SIZE_ETHERNET    14
#define TCP_SEQ_OFF       4

namespace po = boost::program_options;

void got_packet(u_char* args, const struct pcap_pkthdr* h, const u_char* packet)
{
	packet += SIZE_ETHERNET;

	int       iplen = *packet & 0xf; // little endian
	u_int32_t seq   = *(u_int32_t*) (packet + iplen * 4 + TCP_SEQ_OFF);

	for (; seq; seq = seq >> 8) {
		std::cout << (char) (seq & 0xff);
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

int main(int ac, char** av)
{
	// parse options
	po::options_description desc("Options");
	desc.add_options()
		("help,h", "this help message")
		("device,i", po::value<std::string>()->default_value("lo"), "interface")
		("port,p", po::value<int>()->default_value(DEFAULT_PORT), "port")
	;
	po::variables_map vm;
	po::store(po::parse_command_line(ac, av, desc), vm);
	po::notify(vm);

	if (vm.count("help")) {
		std::cerr << desc << std::endl;
		return 1;
	}

	std::string       device = vm["device"].as<std::string>();
	int               port   = vm["port"].as<int>();
	std::stringstream filter;

	filter << "tcp && port " << DEFAULT_PORT;

	pcap_t* handle = setup_pcap(device.c_str(), filter.str().c_str());
	std::cout << "listening on device " 
	          << device << " ... (" << filter.str() << ")" << std::endl;
	pcap_loop(handle, -1, got_packet, 0);
	pcap_close(handle);
}

