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

#include "category.h"
#include "libs/HashMap.h"
#include "libs/flowlist.h"
#include "libs/utils.h"

using namespace std;

typedef hash_map<HashKeyIPv4, uint32_t , HashFunction<HashKeyIPv4>,HashFunction<HashKeyIPv4> > HashMap;
typedef hash_map<HashKeyIPv4_6T, struct flow, HashFunction<HashKeyIPv4_6T>, HashFunction<HashKeyIPv4_6T> > FlowHashMap6;

class CPersist {
public:
	bool test;
	bool verbose;
	bool verbose2;
	bool use_outflows;

	C_Category::C_Category_set c;
	C_Category::C_Category_rc_signs rc;	///< For per-rule sign accounting
	C_Category::C_Category_rc_signs rc2;///< For per-class sign accounting

	uint32_t * flows;			///< Flow count per rule (rule number is index)
	uint32_t * packets;		///< Packet count per rule (rule number is index)
	uint64_t * bytes;			///< Byte count per rule (rule number is index)

	uint32_t * flows2;		///< Flow count per class (class number is index)
	uint32_t * packets2;		///< Packet count per class (class number is index)
	uint64_t * bytes2;		///< Byte count per class (class number is index)

	vector<FlowHashMap6 *> hashedFlowlist;

	ofstream fr_outfs;		///< Flows per rule statistics file (as fractions of flows)
	ofstream fc_outfs;		///< Flows per class statistics file (as fractions of flows)

	ofstream fr_outfs_frac;		///< Flows per rule statistics file
	ofstream fc_outfs_frac;		///< Flows per class statistics file

	HashMap all_srcIP_hm;	///< Hash map to determine unique src IPs over all ow flows
	HashMap all_dstIP_hm;	///< Hash map to determine unique dst IPs over all ow flows

	uint16_t all_dstPort_arr[65536];
	vector<uint16_t *> dstPort_arr;	// Per rule maintain an array for flows per dst port number
	vector<uint16_t *> dstPort_arr2;	// Per class maintain an array for flows per dst port number

	HashMap * srcIP_hm;		///< Array of hash maps to determine unique src IPs per-rule
	HashMap * dstIP_hm;		///< Array of hash maps to determine unique dst IPs per-rule
	HashMap * srcIP_hm2;		///< Array of hash maps to determine unique src IPs per-class
	HashMap * dstIP_hm2;		///< Array of hash maps to determine unique dst IPs per-class

	vector<ofstream *> sr_outfs;	// Signs per rule  statistics file
	vector<ofstream *> sc_outfs;	// Signs per class  statistics file

	vector<ofstream *> sr_outfs_frac;	// Signs per rule  statistics file (as fractions of flows)
	vector<ofstream *> sc_outfs_frac;	// Signs per class  statistics file (as fractions of flows)


	CPersist(string & date_time, bool verbose, bool verbose2, bool test,
		string & rules_filename, string & classes_filename, bool use_outflows);

	~CPersist();
};

#endif /* CPERSIST_H_ */
