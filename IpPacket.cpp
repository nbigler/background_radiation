/*
 * IpPacket.cpp
 *
 *  Created on: Oct 1, 2011
 *      Author: bigli
 */


#include "IpPacket.h"
#include <netinet/in.h>

#include <iostream>
#include <cstdlib>

using namespace std;

IpPacket::IpPacket(uint8_t protocol, uint32_t srcIP, uint32_t dstIP): protocol(protocol), srcIP(srcIP), dstIP(dstIP),tcp_hdr(NULL), udp_hdr(NULL) {
}

void IpPacket::setTcpHeader(struct tcphdr * tcp_hdr) {
	if (this->protocol != IPPROTO_TCP) {
		cerr << "TCP Header can only be set for TCP packets!";
		exit(1);
	}
	this->tcp_hdr = tcp_hdr;
}

void IpPacket::setUdpHeader(struct udphdr * udp_hdr) {
	if (this->protocol != IPPROTO_UDP) {
		cerr << "UDP Header can only be set for UDP packets!";
		exit(1);
	}
	this->udp_hdr = udp_hdr;
}

uint8_t IpPacket::getProtocol() {
	return this->protocol;
}


