#ifndef CFLOW_H_
#define CFLOW_H_
/**
 *	\file cflow.h
 *	\brief Compact format for NetFlow records.
 *
 * 	Copyright (c) 2009, Eduard Glatz 
 *
 * 	Author: Eduard Glatz  (eglatz@tik.ee.ethz.ch) 
 *
 *	Distributed under the Gnu Public License version 2 or the modified
 *	BSD license.
 */

#include <stdint.h>	// To include uintN_t types
#include "global.h"

// Compacted flow format (suitable for ipv4 only; size is 40 bytes)
// ================================================================
//
// Additional requirements for files using this format:
// - must use GZIP compression
// - flows must be merged (re-assembled flow fragments)
// - flow list must be sorted in 
//     i) ascending order of srcIP 
//    ii) ascending order of dstIP
//   iii) ascending order of flow start time 
//

#ifdef CFLOW_NOUNION

struct cflow {
	uint32_t localIP; ///< Numeric ip address of source vertex (host byte order)
	uint32_t remoteIP;///< Numeric ip address of destination vertex (host byte order)
	uint64_t startMs;///< Flow start time in milliseconds since the epoch
	uint32_t durationMs;///< Flow duration in milliseconds since the epoch
	uint16_t localPort;///< Source port of vertex
	uint16_t remotePort;///< Destination port of vertex 
	uint64_t dOctets;///< flow size in byte 
	uint32_t dPkts;///< number of packets contained in flow 
	uint16_t localAS;///< source AS 
	uint16_t remoteAS;///< destination AS 
	uint8_t prot;///< protocol type 
	uint8_t dir;///< direction: 0: outgoing, 1: incoming, 2: transit other: invalid
	uint8_t tos_flags;///< ToS flags
	uint8_t magic;///< Magic number (format version)
	uint32_t padding;///< Fill up to next multiple of 8	
};

#else

// We employ anonymous unions with components of equal memory footprint.
// This allows as to access the same members by different names. This is useful when using struct cflow
// for single flows and flow summaries (this is needed during the server role summarization to use
// the same hash map type for single records and summaries)
struct cflow {
	union {
		uint32_t localIP; ///< Numeric ip address of source vertex (host byte order)
		uint32_t serverIP; ///< Numeric ip address of server (host byte order)
		uint32_t clientIP; ///< Numeric ip address of client (host byte order)
	};
	union {
		uint32_t remoteIP; ///< Numeric ip address of destination vertex (host byte order)
		uint32_t connections; ///< Number of connections to a service port	
	};
	uint64_t startMs; ///< Flow start time in milliseconds since the epoch
	union {
		uint32_t durationMs; ///< Flow duration in milliseconds since the epoch
		uint32_t summaryIn; ///< Index into inside summary list (flow membership, summary self-id)
	};
	union {
		uint16_t localPort; ///< Source port of vertex
		uint16_t servicePort; ///< Source port of vertex
	};
	union {
		uint16_t remotePort; ///< Destination port of vertex 
		uint16_t clients; ///< Number of clients accessing this endpoint
	};
	uint64_t dOctets; ///< flow size in byte 
	uint32_t dPkts; ///< number of packets contained in flow 
	union {
		uint32_t summaryOut; ///< Index into outside summary list (flow membership)
		struct {
			uint16_t local;
			uint16_t remote;
		} AS;
	};
//	uint16_t localAS;			///< source AS 
//	uint16_t remoteAS;		///< destination AS 
	uint8_t prot; ///< protocol type 
	union {
		uint8_t dir; ///< direction: for values see enum flow_type_t
		uint8_t flowtype; ///< Flow type
	};
	uint8_t tos_flags; ///< ToS flags
	uint8_t magic; ///< Magic number (format version)
	uint32_t padding; ///< Fill up to next multiple of 8	

	// Methods
	void init(uint32_t localIP, uint16_t localPort, uint32_t remoteIP,
			uint16_t remotePort, uint8_t prot, uint8_t flowtype,
			uint64_t startMs, uint32_t durationMs, uint64_t dOctets,
			uint32_t dPkts) {
		this->localIP = localIP;
		this->localPort = localPort;
		this->remoteIP = remoteIP;
		this->remotePort = remotePort;
		this->prot = prot;
		this->flowtype = flowtype;
		this->startMs = startMs;
		this->durationMs = durationMs;
		this->dOctets = dOctets;
		this->dPkts = dPkts;
		AS.local = 0;
		AS.remote = 0;
		tos_flags = 0;
		magic = 1;
	}

	void init(uint32_t localIP, uint16_t localPort, uint32_t remoteIP,
			uint16_t remotePort, uint8_t prot, uint8_t flowtype,
			uint64_t dOctets, uint32_t dPkts) {
		this->localIP = localIP;
		this->localPort = localPort;
		this->remoteIP = remoteIP;
		this->remotePort = remotePort;
		this->prot = prot;
		this->flowtype = flowtype;
		this->startMs = 0;
		this->durationMs = 0;
		this->dOctets = dOctets;
		this->dPkts = dPkts;
		AS.local = 0;
		AS.remote = 0;
		tos_flags = 0;
		magic = 1;
	}

	void init(uint32_t localIP, uint16_t localPort, uint32_t remoteIP,
			uint16_t remotePort, uint8_t prot, uint8_t flowtype) {
		this->localIP = localIP;
		this->localPort = localPort;
		this->remoteIP = remoteIP;
		this->remotePort = remotePort;
		this->prot = prot;
		this->flowtype = flowtype;
		this->startMs = 0;
		this->durationMs = 0;
		this->dOctets = 0;
		this->dPkts = 0;
		AS.local = 0;
		AS.remote = 0;
		tos_flags = 0;
		magic = 1;
	}
};

// For short
typedef struct cflow cflow_t;

/// Enumeration of distinguished protocols.
enum proto_t {
	UDP, TCP, ICMP, OTHER
};

inline proto_t map_protonum(uint8_t protonum) {
	switch (protonum) {
	case 1: //prot = "ICMP"
		return ICMP;
	case 6: //prot = "TCP "
		return TCP;
	case 17: //prot = "UDP "
		return UDP;
	default:
		return OTHER;
	}
}

// Enum flow type definitions employed as bit masks 
// ------------------------------------------------
// Flow types are assigned to bit positions as follows:
//
// Bitpos. 	Flow Type	Mask Value 	Comment
//
//   0		outflow	 	000001 B (=1)
//   1      inflow      000010 B (=2)
//  0/1		uniflow		000011 B (=3)	Unidirectional flow / transit flow
//   2      biflow      000100 B (=4)	Bidirectional flow
//   3      unibiflow   001000 B (=8) * (see below)
//  0/1/2   allflow     000111 B (=7) 
//  2/3     okflow      001100 B (=12) benign flows (**)
// 0..3		simpleflow	001111 B (=15) mask to get flow type without early/late attributes
//	  5		late			010000 B (=16)	flow exists after current interval
//   6		early		 	100000 B (=32) flow exists before current interval
//  5/6		longstand	110000 B (=48) long-standing flow (mask)
//
// *: uniflow in the presence of one or more biflows between
// involved hosts
// **: based on the assumption that for benign traffic between
// two hosts there has to be at least one biflow beside any
// uniflows

enum flow_type_t {
	outflow = 1,
	inflow = 2,
	uniflow = 3,
	biflow = 4,
	unibiflow = 8,
	allflow = 7,
	q_infl = 10,
	q_outfl = 9,
	okflow = 12,
	simpleflow = 15,
	late = 16,
	early = 32,
	longstand = 48
};

//******************************************************************************************************

#ifdef USE_CFLOWFILTER

/**
 *	\class CFlowFilter
 *
 *	Supports flow filtereing by:
 *	- flow direction type (biflow, inflow, outflow, prod. inflow, prod. outflow)
 *	- protocol (granularity: TCP/UDP/ICMP/OTHER)
 *
 *	A flow filter object defines for each flow contained in flowlist if it 
 *	is filtered or not. For this purpose a boolean aary is initialized at
 *	object construction time. Thus, the filter function is very fast by
 *	just looking up this array by flow number.
 *
 */
class CFlowFilter {
private:
	bool * flow_filter;
	int flow_count;

	uint8_t flowtype_filter;
	uint8_t not_flowtype_filter;

public:
	CFlowFilter(struct cflow * flowlist, int flow_count, prefs_t * prefs);
	~CFlowFilter();
	bool filter_flow(int flow_num);
	bool filter_flow(uint8_t flowtype);
};
#endif // #ifdef USE_CFLOWFILTER

#ifdef USE_SUMMARIES
// Codes for magic field of struct cflow
enum magic_t {
	flow_valid=1, /* Valid flow */
	flow_summarized=20, /* Valid flow that is part of a summary */
	flow_outside=90, /* Flow that is outside of observation interval (either warm-up or cool-down period) */
	flow_obsolete=99, /* Flow marked for deletion */
	summary_valid=100, /* Valid summary */
	summary_obsolete=98 /* Summary marked for deletion */
};
#endif

#endif // CFLOW_NOUNION
#endif // CFLOW_H_
