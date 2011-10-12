#ifndef FLOW_H_
#define FLOW_H_


#include <stdint.h>
#include <vector>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "global.h"



struct ipPayload {
	union {
		struct tcphdr * tcpHeader;
		struct udphdr * udpHeader;
		struct icmphdr * icmpHeader;
	};
	uint64_t timestamp;		///< Timestamp of the packet
	uint64_t packetsize;	///< packet size in byte;
	char const * payload;
};


struct flow {
	uint32_t localIP;		///< Numeric ip address of source vertex (host byte order)
	uint32_t remoteIP;		///< Numeric ip address of destination vertex (host byte order)

	uint16_t localPort;		///< Source port of vertex
	uint16_t remotePort;	///< Destination port of vertex

	uint64_t startMs;		///< Flow  start time in microseconds since the epoch
	uint32_t durationMs;	///< Flow duration in microseconds

	uint64_t dOctets;		///< flow size in byte
	uint32_t dPkts;			///< number of packets containted in flow

	uint8_t protocol;		///< protocl type

	uint8_t flowtype;		///< flow direction: for values see enum flow_type_t

	uint8_t tos_flags;		///< ToS flags
	uint8_t magic;			///< Magic number (format version)

	std::vector<struct ipPayload> payload; ///< IP-payload of each packet in flow

	void init(uint32_t localIP, uint32_t remoteIP, uint8_t protocol,  uint8_t direction) {
		this->localIP = localIP;
		this->remoteIP = remoteIP;
		this->protocol = protocol;
		this->flowtype = direction;
	}

};

#endif // CFLOW_H_
