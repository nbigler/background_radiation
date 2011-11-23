/*
 * CPersist.h
 *
 *  Created on: Oct 11, 2011
 *      Author: nbigler
 */

#ifndef CPERSIST_H_
#define CPERSIST_H_

#include <string>
#include <stdint.h>
#include <iosfwd>
#include <map>

#include "category.h"
#include "libs/HashMap.h"
#include "libs/flowlist.h"
#include "libs/utils.h"
#include "libs/packet.h"
#include "Flow.h"

using namespace std;

//typedef hash_map<HashKeyIPv4, uint32_t , HashFunction<HashKeyIPv4>,HashFunction<HashKeyIPv4> > HashMap;
typedef hash_map<HashKeyIPv4_6T, Flow, HashFunction<HashKeyIPv4_6T>, HashFunction<HashKeyIPv4_6T> > CFlowHashMap6;

class CPersist {
public:
	bool test;
	bool verbose;
	bool verbose2;
	bool use_outflows;

	C_Category::C_Category_set c;
	C_Category::C_Category_rc_signs rc;	///< For per-rule sign accounting

	/*uint32_t * flows;			///< Flow count per rule (rule number is index)
	uint32_t * packets;		///< Packet count per rule (rule number is index)
	uint64_t * bytes;			///< Byte count per rule (rule number is index)*/
	string date;

	time_t last_flow;
	static const int TYPE_COUNT = 255;
	static const int CODE_COUNT = 255;
	static const int PORT_COUNT = 65536;

	long itc[TYPE_COUNT][CODE_COUNT];

	long portlist_local[PORT_COUNT];
	long portlist_remote[PORT_COUNT];

	map<string, int> icmp_false_positives;


	map<string, int> tcp_false_positives;
	map<string, int> tcp_false_negatives;

	map<string, int> scan5_aff_flow_count;
	map<string, int> othermal_aff_flow_count;
	map<string, int> backsc_aff_flow_count;
	map<string, int> sbenign_aff_flow_count;



	vector<CFlowHashMap6*> flows_by_rule;

//	vector<vector<packet> > rules_packetlist;
//	vector<packet> packetlist;

	CPersist(string & date_time, bool verbose, bool verbose2, bool test,
		string & rules_filename, string & classes_filename, bool use_outflows);

	~CPersist();
};

#endif /* CPERSIST_H_ */
