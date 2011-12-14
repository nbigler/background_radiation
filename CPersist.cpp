/*
 * CPersist.cpp
 *
 *  Created on: Oct 11, 2011
 *      Author: nbigler
 */

#include "CPersist.h"
#include "libs/utils.h"

CPersist::CPersist(string & date_time, bool verbose, bool verbose2, bool test,
		string & rules_filename, string & classes_filename)
{
	this->verbose = verbose;
	this->verbose2 = verbose2;
	this->test = test;
	/*flows = packets = NULL;
	bytes = NULL;*/
	date = date_time.substr(0,8);

	// Read rules files if any
	// ***********************
	if (rules_filename.size() > 0) {
		// Get rules from files
		// ====================
		if (!c.get_rules(rules_filename)) {
			cerr << "\nERROR in get_rules(): failed reading rule file.\n";
			exit(1);
		}
		int rule_count = c.get_rule_count();
		if (verbose) cout << "Loaded " << rule_count << " rules.\n";
		rc.init(c.get_enum_count(), rule_count);

		/*flows   = new uint32_t[rule_count];
		packets = new uint32_t[rule_count];
		bytes   = new uint64_t[rule_count];*/
	}
}



/**
  * 	Destructor
  */
CPersist::~CPersist()
{
	/*delete[] flows;
	delete[] packets;
	delete[] bytes;*/
}
