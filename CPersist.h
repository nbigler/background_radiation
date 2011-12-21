/**
 *	\file CPersist.cpp
 *
 *	\brief Implements the CPersist class that keeps data persistent over all processing intervals.
 *
 *
 * 	Copyright (c) 2010, Eduard Glatz, Nicolas Bigler, Michael Fisler
 *
 * 	Authors: Eduard Glatz  (eglatz@tik.ee.ethz.ch)
 * 			 Nicolas Bigler (nbigler@hsr.ch)
 * 			 Michael Fisler (mfisler@hsr.ch)
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

typedef hash_multimap<HashKeyIPv4_6T, Flow, HashFunction<HashKeyIPv4_6T>,
		HashFunction<HashKeyIPv4_6T> > CFlowHashMultiMap6;

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
	C_Category::C_Category_rc_signs rc; ///< For per-rule sign accounting

	string date;

	map<string, int> scan_validation_flow_count;
	map<string, int> othermal_validation_flow_count;
	map<string, int> backsc_validation_flow_count;
	map<string, int> unreach_validation_flow_count;
	map<string, int> p2p_validation_flow_count;
	map<string, int> sbenign_validation_flow_count;
	map<string, int> other_validation_flow_count;

	CFlowHashMultiMap6* flowHashMap;

	vector<packet> packets;
	vector<packet> matched_packets;

	CPersist(string & date_time, bool verbose, bool verbose2,
			string & rules_filename);

	~CPersist();
};

#endif /* CPERSIST_H_ */
