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

#include "CPersist.h"
#include "libs/utils.h"

/**
  *	Constructor
  *
  *	\param	date_time	      Date/time string using format YYYYMMDD.hhmm
  *	\param	verbose		      Create informative messages
  *	\param	verbose2		      Create more informative messages
  *	\param	test			      When TRRUE then show basic statistics and performa a sanitiy check
  *	\param	rules_filename		Name of file containing rules
  */
CPersist::CPersist(string & date_time, bool verbose, bool verbose2,	string & rules_filename)
{
	this->verbose = verbose;
	this->verbose2 = verbose2;

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
	}
}


/**
  * 	Destructor
  */
CPersist::~CPersist()
{
}
