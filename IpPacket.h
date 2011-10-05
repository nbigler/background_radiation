/*
 * IpPacket.h
 *
 *  Created on: Oct 1, 2011
 *      Author: bigli
 */

#ifndef IPPACKET_H_
#define IPPACKET_H_


#include <netinet/ip.h>

class IpPacket {
public:
	IpPacket(uint8_t protocol, uint32_t srcIP, uint32_t dstIP);
	void setTcpHeader(struct tcphdr * tcp_hdr);
	void setUdpHeader(struct udphdr * udp_hdr);
	uint8_t getProtocol();
private:
	uint32_t srcIP;
	uint32_t dstIP;
	struct tcphdr * tcp_hdr;
	struct udphdr * udp_hdr;
	uint8_t protocol;
};

#endif /* IPPACKET_H_ */
