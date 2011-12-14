/**
  *	\file CPersist.cpp
  *
  *	\brief Implements the CPersist class that keeps data persistent over all processing intervals.
  *
  *
  * 	Copyright (c) 2010, Eduard Glatz
  *
  * 	Author: Eduard Glatz  (eglatz@tik.ee.ethz.ch)
  *
  *	Distributed under the Gnu Public License version 2 or the modified
  *	BSD license.
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
//typedef hash_map<HashKeyIPv4_6T, Flow, HashFunction<HashKeyIPv4_6T>, HashFunction<HashKeyIPv4_6T> > CFlowHashMap6;

typedef hash_multimap<HashKeyIPv4_6T, Flow, HashFunction<HashKeyIPv4_6T>, HashFunction<HashKeyIPv4_6T> > CFlowHashMultiMap6;

/**
  *	\class	CPersist
  *	Keeps data persistent over all processing intervals.
  */
class CPersist {
public:
	bool test;
	bool verbose;
	bool verbose2;

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

	map<string, int> scan5_validation_flow_count;
	map<string, int> othermal_validation_flow_count;
	map<string, int> backsc_validation_flow_count;
	map<string, int> sbenign_validation_flow_count;



	vector<CFlowHashMultiMap6*> flows_by_rule;

	CPersist(string & date_time, bool verbose, bool verbose2, bool test,
		string & rules_filename);

	~CPersist();
};

#endif /* CPERSIST_H_ */
