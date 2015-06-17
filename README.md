# Raw socket programming examples
This is a small collection of example how to do Linux raw socket programming in C/C++. The exampless have been tested with Ubuntu on an Intel CPU which is little-endian architecture. It is very likely that these example do not work on big-endian architectures (e.g. ARM).
* `icmp` : example how to send a ICMP packet (echo request)
* `tcpsyn` : example how to send a SYN packet
* `tcpsyn_simple_chat` : example how to realize a simple chat via SYN packets only
* `udp` : example how to send a syslog message via an UDP packet
* `ipudp` : example how to send a syslog message via an UDP packet with a faked source IP
