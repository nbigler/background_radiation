/**
  *	\file CPersist.cpp
  *
  *	\brief Implements the CPersist class that keeps data persistent over all processing intervals.
  *
  *
  * 	Copyright (c) 2010, Eduard Glatz, Nicolas Bigler, Michael Fisler
  *
  * 	Authors: Eduard Glatz  (eglatz@tik.ee.ethz.ch)
  *				 Nicolas Bigler (nbigler@hsr.ch)
  *				 Michael Fisler (mfisler@hsr.ch)
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

typedef hash_multimap<HashKeyIPv4_6T, Flow, HashFunction<HashKeyIPv4_6T>, HashFunction<HashKeyIPv4_6T> > CFlowHashMultiMap6;

/**
  *	\class	CPersist
  *	Keeps data persistent over all processing intervals.
  */
class CPersist {
public:
	bool verbose;
	bool verbose2;

	C_Category::C_Category_set c;
	C_Category::C_Category_rc_signs rc;	///< For per-rule sign accounting

	string date;

	time_t last_flow;

	vector<CFlowHashMultiMap6*> flows_by_rule;

	vector<vector<packet> *> rules_packetlist;

	CPersist(string & date_time, bool verbose, bool verbose2, string & rules_filename);

	~CPersist();
};

#endif /* CPERSIST_H_ */
