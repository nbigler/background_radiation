/*
 * CPersist.cpp
 *
 *  Created on: Oct 11, 2011
 *      Author: nbigler
 */

#include "CPersist.h"
#include "libs/utils.h"

CPersist::CPersist(string & date_time, bool verbose, bool verbose2, bool test,
		string & rules_filename, string & classes_filename, bool use_outflows)
{
	this->verbose = verbose;
	this->verbose2 = verbose2;
	this->test = test;
	this->use_outflows = use_outflows;
	flows = packets = NULL;
	bytes = NULL;
	srcIP_hm = dstIP_hm = NULL;

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

		flows   = new uint32_t[rule_count];
		packets = new uint32_t[rule_count];
		bytes   = new uint64_t[rule_count];

		srcIP_hm = new HashMap[rule_count];
		dstIP_hm = new HashMap[rule_count];

		// Create csv files
		// ================

		// 1. flows per rule statistics
		// ----------------------------
		string date = date_time.substr(0,8);
		string rules_csv_fname = "rules_signs_" + date + ".csv";
		string rules_csv_fname_frac = "rules_signs_frac_" + date + ".csv";
		// Create files
		util::open_outfile(fr_outfs, rules_csv_fname);
		util::open_outfile(fr_outfs_frac, rules_csv_fname_frac);
		// Add csv header line
		fr_outfs << "interval, start";
		fr_outfs_frac << "interval, start";

		for (int k=0; k < rule_count; k++) {
			string rule_name;
			c.get_rule_name(k, rule_name);
			fr_outfs << ", " << rule_name;
			fr_outfs_frac << ", " << rule_name;
		}
		fr_outfs << ", flows, packets, bytes";
		fr_outfs_frac << ", flows, packets, bytes";

		fr_outfs << ", srcIPs, dstIPs, dstPorts, dstPorts3, dstPorts5";
		fr_outfs_frac << ", srcIPs, dstIPs, dstPorts, dstPorts3, dstPorts5";

		fr_outfs << ", r_dIP_sIP, r_pkt_flow, r_byte_pkt";
		fr_outfs_frac << ", r_dIP_sIP, r_pkt_flow, r_byte_pkt";

		fr_outfs << endl;
		fr_outfs_frac << endl;

		// 2. Signs per rule
		// -----------------
		// Prepare a file for each rule

		// For each rule
		for (int i=0; i<c.get_rule_count(); i++) {
			// Derive file name from rule name
			string rulename;
			if (!c.get_rule_name(i, rulename)) {
				cerr << "ERROR: unable to get rule name for rule number " << i << endl;
			}
			string filename = "rule_" + rulename + "_signs_" + date + ".csv";
			string filename_frac = "rule_" + rulename + "_signs_frac_" + date + ".csv";
			// Open file and add to out streams vector
			ofstream * outfs = new ofstream;
			ofstream * outfs_frac = new ofstream;
			util::open_outfile(*outfs, filename);
			util::open_outfile(*outfs_frac, filename_frac);
			sr_outfs.push_back(outfs);
			sr_outfs_frac.push_back(outfs_frac);
			// Add CSV header line
			(*outfs) << "interval, start, ";
			(*outfs_frac) << "interval, start, ";

			c.print_enums_csv(*outfs);
			c.print_enums_csv(*outfs_frac);

			(*outfs) << ", flows, packets, bytes";
			(*outfs_frac) << ", flows, packets, bytes";

			(*outfs) << ", srcIPs, dstIPs, dstPorts, dstPorts3, dstPorts5";
			(*outfs_frac) << ", srcIPs, dstIPs, dstPorts, dstPorts3, dstPorts5";

		   (*outfs) << ", r_dIP_sIP, r_pkt_flow, r_byte_pkt";
		   (*outfs_frac) << ", r_dIP_sIP, r_pkt_flow, r_byte_pkt";

			(*outfs) << endl;
			(*outfs_frac) << endl;

			// Prepare a dst port arr per rule
			uint16_t * arr = new uint16_t[65536];
			dstPort_arr.push_back(arr);
		}
	}

	// Read classes files if any
	if (classes_filename.size() > 0) {
		if (rules_filename.size() == 0) {
			cerr << "ERROR: cannot procss classes without loaded rules file.\n";
			exit(1);
		}
		// Get classes from files
		// ======================
		if (!c.get_classes(classes_filename)) {
			cerr << "\nERROR in get_classes(): failed reading class definition file.\n";
			exit(1);
		}
		int class_count = c.get_class_count();
		if (verbose) cout << "Loaded " << class_count << " class definitions.\n";

		rc2.init(c.get_enum_count(), class_count+1);	// Add class "other" having no definition

		flows2   = new uint32_t[class_count+1];
		packets2 = new uint32_t[class_count+1];
		bytes2   = new uint64_t[class_count+1];

		srcIP_hm2 = new HashMap[class_count+1];
		dstIP_hm2 = new HashMap[class_count+1];

		// Create csv files
		// ================

		// 1. flows per class statistics
		// ----------------------------
		string date = date_time.substr(0,8);
		string classes_csv_fname = "classes_signs_" + date + ".csv";
		string classes_csv_fname_frac = "classes_signs_frac_" + date + ".csv";
		// Create file
		util::open_outfile(fc_outfs, classes_csv_fname);
		util::open_outfile(fc_outfs_frac, classes_csv_fname_frac);
		// Add csv header line
		fc_outfs << "interval, start";
		fc_outfs_frac << "interval, start";

		for (int k=0; k < class_count; k++) {
			string class_name;
			c.get_class_name(k, class_name);
			fc_outfs << ", " << class_name;
			fc_outfs_frac << ", " << class_name;
		}
		fc_outfs << ", other"; // Add class "other" having no definition
		fc_outfs_frac << ", other"; // Add class "other" having no definition

		fc_outfs << ", flows, packets, bytes";
		fc_outfs_frac << ", flows, packets, bytes";

		fc_outfs << ", srcIPs, dstIPs, dstPorts, dstPorts3, dstPorts5";
		fc_outfs_frac << ", srcIPs, dstIPs, dstPorts, dstPorts3, dstPorts5";

		fc_outfs << ", r_dIP_sIP, r_pkt_flow, r_byte_pkt";
		fc_outfs_frac << ", r_dIP_sIP, r_pkt_flow, r_byte_pkt";

		fc_outfs << endl;
		fc_outfs_frac << endl;

		// 2. Signs per class
		// ------------------
		// Prepare a file for each class

		// For each class
		for (int i = 0; i <= class_count; i++) { // Add class "other" having no definition
			// Derive file name from class name
			string classname;
			if (i==class_count) {
				classname = "other"; // Add class "other" having no definition
			} else if (!c.get_class_name(i, classname)) {
				cerr << "ERROR: unable to get class name for class number " << i << endl;
			}
			string filename = "class_" + classname + "_signs_" + date + ".csv";
			string filename_frac = "class_" + classname + "_signs_frac_" + date + ".csv";
			// Open file and add to out streams vector
			ofstream * outfs = new ofstream;
			ofstream * outfs_frac = new ofstream;
			util::open_outfile(*outfs, filename);
			util::open_outfile(*outfs_frac, filename_frac);
			sc_outfs.push_back(outfs);
			sc_outfs_frac.push_back(outfs_frac);
			// Add CSV header line
			(*outfs) << "interval, start, ";
			(*outfs_frac) << "interval, start, ";

			c.print_enums_csv(*outfs);
			c.print_enums_csv(*outfs_frac);

			(*outfs) << ", flows, packets, bytes";
			(*outfs_frac) << ", flows, packets, bytes";

			(*outfs) << ", srcIPs, dstIPs, dstPorts, dstPorts3, dstPorts5";
			(*outfs_frac) << ", srcIPs, dstIPs, dstPorts, dstPorts3, dstPorts5";

			(*outfs) << ", r_dIP_sIP, r_pkt_flow, r_byte_pkt";
			(*outfs_frac) << ", r_dIP_sIP, r_pkt_flow, r_byte_pkt";

			(*outfs) << endl;
			(*outfs_frac) << endl;

			// Prepare a dst port arr per class
			uint16_t * arr = new uint16_t[65536];
			dstPort_arr2.push_back(arr);
		}
	}
}



/**
  * 	Destructor
  */
CPersist::~CPersist()
{
	fr_outfs.close();
	fr_outfs_frac.close();
	for (int i=0; i<sr_outfs.size(); i++) {
		sr_outfs[i]->close();
		sr_outfs_frac[i]->close();
		delete sr_outfs[i];
		delete sr_outfs_frac[i];
		delete[] dstPort_arr[i];
	}
	fc_outfs.close();
	fc_outfs_frac.close();
	for (int i=0; i<sc_outfs.size(); i++) {
		sc_outfs[i]->close();
		sc_outfs_frac[i]->close();
		delete sc_outfs[i];
		delete sc_outfs_frac[i];
		delete[] dstPort_arr2[i];
	}
	delete[] flows;
	delete[] packets;
	delete[] bytes;
	delete[] flows2;
	delete[] packets2;
	delete[] bytes2;

	delete[] srcIP_hm;
	delete[] dstIP_hm;
	delete[] srcIP_hm2;
	delete[] dstIP_hm2;
}
