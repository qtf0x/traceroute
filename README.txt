Programming Project 4 - Traceroute

Author: Vincent Marias <vmarias@mines.edu>

Simple version of the "traceroute" utility. Using RAW sockets, we build custom
datagrams and pass them directly to the link layer. By manually setting the
time-to-live in the IPv4 header, we can send ICMP Echo Requests to each of the
hops along the route to a destination address. Each time an ICMP TTL Exceeded
datagram arrives, we increment the TTL by 1 and resend. By recording the source
address of each response, we can trace the route of all the hops our datagram
takes as it travels to the desintation IP address.

Usage:

cd /DIRECTORY/CONTAINING/vmarias.tgz
tar -zxf vmarias.tgz
cd vmarias
make
sudo ./traceroute -d [address] -v [log level]
