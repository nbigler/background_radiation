#ifndef PACKET_H_
#define PACKET_H_
/**
  *	\file packet.h
  *	\brief Compact form of network packets
  *
  * 	Copyright (c) 2011, Nicolas Bigler, Michael Fisler
  *
  * 	Author: Nicolas Bigler (nbigler@hsr.ch)
  * 			Michael Fisler (mfisler@hsr.ch)
  *
  *	Distributed under the Gnu Public License version 2 or the modified
  *	BSD license.
  */

#include <stdint.h>
#include <vector>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "global.h"

/**
 * struct that containts the tcp, udp or icmp header
 */
struct ipPayload {
	union {
		struct tcphdr tcpHeader;
		struct udphdr udpHeader;
		struct icmphdr icmpHeader;
	};
};

/**
 * struct that containts information about a packet
 */
struct packet {
	struct ethhdr ethHeader;
	struct iphdr ipHeader;

	uint32_t srcIP;		///< Numeric ip address of source vertex (host byte order)
	uint32_t dstIP;		///< Numeric ip address of destination vertex (host byte order)

	uint16_t srcPort;		///< Source port of vertex
	uint16_t dstPort;	///< Destination port of vertex

	uint8_t protocol;		///< protocl type

	uint64_t timestamp;		///< Timestamp of the packet
	uint32_t packetsize;	///< Packet size in byte
	uint32_t actualsize;	///< Captured packet size

	struct ipPayload ipPayload; ///< IP-payload of each packet in flow

	/**
		 * Initializes the struct
		 * @param srcIP		Source IP of the packet
		 * @param dstIP		Destination IP of the packet
		 * @param protocol	IPv4 Protocol type of the packet
		 */
	void init(uint32_t srcIP, uint32_t dstIP, uint8_t protocol) {
		this->srcIP = srcIP;
		this->dstIP = dstIP;
		this->protocol = protocol;
	}

};

#endif // FLOW_H_
