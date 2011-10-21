/**
  *	\file category.cpp
  *
  *	\brief Implements a number of categories through an enum type and provides a counting 
  *	facility for any combination of the categories. This is useful when an entity is 
  *	assigned to more than one category at a time and, thus, intersections between the 
  *	different category sets have to be tracked.
  *
  *
  * 	Copyright (c) 2010, Eduard Glatz 
  * 
  * 	Author: Eduard Glatz  (eglatz@tik.ee.ethz.ch) 
  *
  *	Distributed under the Gnu Public License version 2 or the modified
  *	BSD license.
  */

/*
Compile for unit test:

g++ category.cpp libs/utils.cpp -o category -DUNIT_TEST

or (with more categories)

g++ category.cpp libs/utils.cpp -o category -DUNIT_TEST2


*/

#include <sstream>
#include <cstdlib>

#include "libs/utils.h"
#include "category.h"



using namespace std;



C_Category::C_Category_set::C_Category_set(unsigned int c) 
{ 
	string enames(category_enum_vals_str);
	cset = c; 

	std::string tmp;
	ecnt = 1;
	for (size_t i=0; i < enames.size(); i++) {
		if (enames[i]==',') {
			category_t_str.push_back(tmp);
			tmp.clear();
			ecnt++;
		} else {
			tmp +=  enames[i];
		}
	}
	if (tmp.size()>0) category_t_str.push_back(tmp);	// Finish off
//					std::cout << "Found " << ecnt << " (" << category_t_str.size() << ") category names.\n";
}



// Print all names of enum type values to console (or a given stream)
void C_Category::C_Category_set::print(ostream & outfs) {
	unsigned int v = cset;
	int pos = 0;
	bool first = true;
	while (v >  0) {
		if (v & 1) { 
			if (pos >= ecnt) {
				cerr << "ERROR: element position pos=" << pos;
				cerr << " exceeds enum range ecnt=" << ecnt << endl;
				break;
			}
			outfs << (!first ? "_" : "");
			outfs << category_t_str.at(pos); 
			first = false;
		}
		v = v>>1;
		pos++;
	}
}


/**
  *	Read a set of rules from a text file. Every rule defines which signs
  *	must be present or absent in a given set to match the rule.
  *
  *	\param Name of rule text file
  *
  *	\return TRUE if success, FALSE in case of errors.
  */
bool C_Category::C_Category_set::get_rules(string & rules_filename)
{
	ifstream infs;
	util::open_infile(infs, rules_filename);

	while (infs.good()) {	
		char buf[65536];
		infs.getline(buf, sizeof(buf));	
		if (!infs.good()) break;	// No new line available
		string line = buf;
		if (line.size()==0) break;	// Handle empty line
		// Process a rule
		stringstream ss;
		ss << line;
		vector<string> rule;
		// Get rule name
		string rulename="";
		ss >>	rulename;
		int size = rulename.size();
		if (size<2 || rulename[size-1]!=':') {
			// No rule name found
			cerr << "Missing rule name in line: " << line << "\n\n";
			return false;
		}
		// Add rule name as first entry rule vector
		rule.push_back(rulename.substr(0,size-1));
		// Now, add all signs to rule vector
		string sign = "";
		while(1) {
			ss >> sign;
			if (sign.size()==0) {
				break;
			} else {
				rule.push_back(sign);
				sign = "";
			}
		}

		if (rule.size() < 2) {
			// Too short: just rule name, but no signs
			return false;
		}

		// Add rule vector to rule set
		rule_set.push_back(rule);
	}

	infs.close();

	// Initialize bit mask arrays needed by "rule_match()".
	load_bitmasks();

	return true;
}



/**
  *	Load bit masks according to rule set currently stored in "rule_set".
  */
void C_Category::C_Category_set::load_bitmasks()
{
	// For each rule
	for (size_t i=0; i<rule_set.size(); i++) {
		unsigned int mask1=0;
		unsigned int mask2=0;
		// For each sign
		for (size_t k=1; k<rule_set[i].size(); k++) {
			string cur_sign = rule_set[i][k];
			bool pos = true;
			if (cur_sign.size()>0 && cur_sign[0]=='!') {
				pos=false;
				cur_sign = cur_sign.substr(1);	// Remove leading "!"-character
			}

			int bitpos = get_enum_by_name(cur_sign);
			if (bitpos==-1) {
				cerr << "C_Category::C_Category_set::load_bitmasks(): cannot find sign \"";
				cerr << cur_sign << "\" in loaded rule set.\n";
				exit(1);
			}

			if (pos) {
				// Add to mask1
				mask1 |= (1<<bitpos);
			} else {
				// Add to mask2
				mask2 |= (1<<bitpos);
			}
		}
		mask_arr1.push_back(mask1);
		mask_arr2.push_back(mask2);
	}
}



void C_Category::C_Category_set::show_masks()
{
	for (size_t i=0; i<mask_arr1.size(); i++) {
		if (i>0) cout << ", ";
		cout << hex << mask_arr1[i];
	}
	cout << endl;
	for (size_t i=0; i<mask_arr2.size(); i++) {
		if (i>0) cout << ", ";
		cout << hex << mask_arr2[i];
	}
	cout << dec << endl;
}




/**
  *	Get numeric enum value fo a given sign name (enum value name).
  *
  *	\param sign_name Name fo a sign 
  *
  *	\return Numeric enum value (bit position) of a sign
  *		     or -1 if sign name not found.
  */
int C_Category::C_Category_set::get_enum_by_name(string & sign_name) {
	int sign_count = category_t_str.size();
	for (int i=0; i<sign_count; i++) {
		if (sign_name.find(category_t_str[i])!=string::npos) {
			return i;
		}
	}
	return -1;
}



/**
  *	Get internal rule number associated with a rule name.
  *	This number is needed to invoke "rule_match()" on the correct rule.
  *
  *	\param rule_name Name of rule to search for
  *
  *	\return Internal rule number (zero-based) or -1 if not found.
  */
int C_Category::C_Category_set::get_rule_number(string & rule_name)
{
	// Column 0 of matrix "rule_set" contains sign names
	for (size_t i = 0; i < rule_set.size(); i++) {
		if (rule_set[i][0].find(rule_name)!=string::npos) {
			return i;
		}
	}
	// Obviously not found rule name
	return -1;
}



/**
  *	Get text name of a loaded rule.
  *
  *	\param rule_num Number of rule (as returned by get_rule_number())
  *
  *	\return TRUE if rule found, FALSe otherwise.
  */
bool C_Category::C_Category_set::get_rule_name(size_t rule_num, std::string & rule_name)
{
	if (rule_num >= rule_set.size()) return false;
	rule_name = rule_set[rule_num][0];
	return true;	
}



/**
  *	Test if a given sign set matches a particular rule .
  *
  *	\param rule_num Internal rule number (can be obtained by get_rule_number())
  *	\param  cset A sign set to test against rule
  *
  *	\return TRUE if sign set matches rule, FALSE otherwise.
  */
bool C_Category::C_Category_set::rule_match(size_t rule_num, unsigned int cset)
{
	// Check if all required signs for requested rule are present in "cset"
	if ((cset & mask_arr1[rule_num]) != mask_arr1[rule_num]) return false;

	// Check if all forbidden signs for requested rule are absent in "cset"
	if ((cset & mask_arr2[rule_num]) != 0) return false;

	// Its a rule match
	return true;
}


//********************************************************************************************

C_Category::C_Category_rc_signs::C_Category_rc_signs()
{
	enum_count = 0;
	rc_count = 0;
}



void C_Category::C_Category_rc_signs::init(int enum_count, int rc_count)
{
	this->enum_count = enum_count;
	this->rc_count = rc_count;

	for (int i=0; i<rc_count; i++) {
		long long * counter = new long long[enum_count];
		for (int j=0; j<enum_count;j++) counter[j] = 0;
		rc_signs.push_back(counter);	// Add per rule or class sign array
	}
}


C_Category::C_Category_rc_signs::~C_Category_rc_signs()
{
	for (size_t i=0; i<rc_signs.size(); i++) {
		delete rc_signs[i];
	}
}


/**
  *	Clear rc_signs counters.
  */
void C_Category::C_Category_rc_signs::reset()
{
	for (size_t i=0; i<rc_signs.size(); i++) {
		for (int j=0; j<enum_count; j++) {
			rc_signs[i][j] = 0;
		}
	}
}



/**
  *	Imcrement enum counters of given rule or class for any enums contained in cset.
  */
void C_Category::C_Category_rc_signs::increment(int rc_number, unsigned int cset)
{
	// Update per enum counter
	for (int i=0; i<=enum_count; i++) {
		if ((cset & 1)!=0) {
			rc_signs[rc_number][i]++;
		}
		cset = cset >> 1;
	}
}


/**
  *	Write per-enum counts (flows) as CSV data to output stream.
  *
  */
void C_Category::C_Category_rc_signs::write_csv(ofstream * outfs, int rc_number)
{
	for (int i=0; i<enum_count; i++) {
		(*outfs) << rc_signs[rc_number][i];
		if (i!=enum_count-1) (*outfs) << ", ";
	}
}


/**
  *	Write per-enum counts (flows) as CSV data to output stream.
  *	(Use fraction of all one-way flows)
  */
void C_Category::C_Category_rc_signs::write_csv(ofstream * outfs, int rc_number, uint32_t flows)
{
	for (int i=0; i<enum_count; i++) {
		uint32_t count = rc_signs[rc_number][i];
		(*outfs) << (double)count/(double)flows;
		if (i!=enum_count-1) (*outfs) << ", ";
	}
}


//********************************************************************************************

C_Category::C_Category()
{
	num_counters = 1 << (1 + e_category::Unknown);
	cout << "num_counters (combinations) =" << num_counters << endl;
	ccounters = new long long[num_counters];
	memset(ccounters, 0, num_counters*sizeof(long long));

	num_enums = 1 + e_category::Unknown;
	ecounters = new long long[num_enums];
	memset(ecounters, 0, num_enums*sizeof(long long));
}



C_Category::~C_Category()
{
	delete ccounters;
	ccounters = NULL;
	delete ecounters;
	ecounters = NULL;
}



void C_Category::increment(C_Category_set combi)
{
	// Update per combination counter
	unsigned int v = combi.get_set();
	if (v==0) v = e_category::Unknown;	// Treat empty set as "Unknown"
	ccounters[v]++; 
	
	// Update per enum counter
	for (int i=0; i<=e_category::Unknown; i++) {
		if ((v & 1)!=0) {
			ecounters[i]++;
		}
		v = v >> 1;
	}
}



void C_Category::print_counters()
{
	for (int i = 1; i < num_counters; i++) {
		if (ccounters[i]==0) continue;	// Skip zeroes
		cout << "cnt=";
		cout << ccounters[i] << " for ";
		C_Category_set s(i);	
		s.print();
		cout << "(" << i << hex << ", 0x" << i << dec << ")\n";
//		cout << "(" << i << ")\n";
	}
}



void C_Category::print_counters_full()
{
	for (int i = 1; i < num_counters; i++) {
		cout << "cnt=";
		cout << ccounters[i] << " for ";
		C_Category_set s(i);	
		s.print();
		cout << "(" << i << hex << ", 0x" << i << dec << ")\n";
	}
}


void C_Category::clear()
{
	memset(ccounters, 0, num_counters*sizeof(long long));
}


//**************************************************************************************
// Test using a toy sign and rule set.
//**************************************************************************************

#ifdef UNIT_TEST

bool check_rules(C_Category::C_Category_set & c, unsigned int cset, 
		bool r1, bool r2, bool r3, bool r4, bool r5)
{
	bool ok = true;

	bool c1 = c.rule_match(0, cset);
	if (c1 != r1) ok = false;

	bool c2 = c.rule_match(1, cset);
	if (c2 != r2) ok = false;

	bool c3 = c.rule_match(2, cset);
	if (c3 != r3) ok = false;

	bool c4 = c.rule_match(3, cset);
	if (c4 != r4) ok = false;

	bool c5 = c.rule_match(4, cset);
	if (c5 != r5) ok = false;

	if (!ok) {
		cout << "[cset=" << cset << "]";
		cout << "{" <<(c1 ? "true, " : "false, ") <<  (c2 ? "true, " : "false, ") << (c3 ? "true, " : "false, ");
		cout << (c4 ? "true, " : "false, ") <<  (c5 ? "true" : "false") << "}\n";
	}
	return ok;
}



// This is not a systematic test, but a simple functional test.
int main()
{
	cout << "\nTEST 1: create set and add signs\n";
	cout <<   "********************************\n";

	C_Category C;
	C_Category::C_Category_set a;

	cout << "\nCreate example sign sets:\n";
	// Create set { Unknown, PortScan }
	// and increment counters of "C" with it.

	a.add(e_category::Unknown);
	a.add(e_category::PortScan);

	cout << "a=";
	a.print();
	C.increment(a);

	// Create set { Unknown, DoS }
	// and increment counters of "C" with it.
	a.clear();
	a.add(e_category::Unknown);
	a.add(e_category::DoS);
	cout << "\na=";
	a.print();
	C.increment(a);

	//Create set { Unknown, DoS }
	// and increment counters of "C" with it.
	a.clear();
	a.add(e_category::Unknown);
	a.add(e_category::DoS);
	cout << "\na=";
	a.printnl();
	C.increment(a);

	// Now show resulting final sign counts of "C"
	C.print_counters();

	cout << "\nTEST 2: show resulting CSV header and data line\n";
	cout <<   "***********************************************\n";

	cout << "\nCSV header = ";
	C.print_csv_header(cout);
	cout << "\nCSV data = ";
	C.print_csv_data(cout);

	cout << "\nPer enum counts:\n";
	C.print_csv_header_cat();
	C.print_csv_data_cat();


	cout << "\nTEST 3: check rule & class matching\n";
	cout <<   "***********************************\n";

	// Firstly, create test rule file
	ofstream outfs;
	string ofname = "ruletest0.txt";
	util::open_outfile(outfs, ofname);
	outfs << "rule1: SweepScan !PortScan !DoS\n";
	outfs << "rule2: PortScan DoS !SweepScan\n";
	outfs << "rule3: SweepScan PortScan !DoS\n";
	outfs << "rule4: !SweepScan PortScan !DoS\n";
	outfs << "rule5: Unknown\n";
	outfs.close();

	C_Category::C_Category_set c;
	if (!c.get_rules(ofname)) {
		cerr << "\nERROR in get_rules(): failed reading rule file.\n";
		exit(1);
	}
	cout << "Successfully loaded " << c.get_rule_count() << " rules.\n";

	cout << "Masks:\n";
	c.show_masks();

	// Next, create test class file
	ofstream outfs2;
	string ofname2 = "classtest0.txt";
	util::open_outfile(outfs2, ofname2);
	outfs2 << "class1: rule1 rule2\n";
	outfs2 << "class2: rule3 rule4\n";
	outfs2 << "class3: rule5\n";
	outfs2.close();

	if (!c.get_classes(ofname2)) {
		cerr << "\nERROR in get_classes(): failed reading classes file.\n";
		exit(1);
	}

	cout << "Successfully loaded " << c.get_class_count() << " class definitions.\n";


	// Check if correct rule numbers are returned
	// (we expect one less than rule number due to zero-based to vector indexing)
	cout << "\nRule number check:\n";
	string c1 = "rule1";
	bool ok = true;
	if (c.get_rule_number(c1) != 0) ok = false;;
	string c4 = "rule4";
	if (c.get_rule_number(c4) != 3) ok = false;;
	string c9 = "rule9";
	if (c.get_rule_number(c9) != -1) ok = false;;
	if (ok) cout << "* passed.\n"; else cout << "* failed.\n";

	// Create a number of test sets and check them against rules
	c.set(0);
	ok = true;
	bool ok2 = true;

	cout << "\nSign set vs. rule check:\n";
	unsigned int cset1 = (1<<e_category::Unknown);
	if (!check_rules(c, cset1, false, false, false, false, true)) ok = false; // Fits rule 5
	if (!c.class_match(2, cset1)) ok2 = false;

	unsigned int cset2 = (1<<e_category::DoS);
	if (!check_rules(c, cset2, false, false, false, false, false)) ok = false; // Fits no rule
	if (c.class_match(0, cset2) || c.class_match(1, cset2) || c.class_match(2, cset2)) ok2 = false;

	unsigned int cset3 = (1<<e_category::PortScan);
	if (!check_rules(c, cset3, false, false, false, true, false)) ok = false; // Fits rule 4
	if (!c.class_match(1, cset3)) ok2 = false;

	unsigned int cset4 = (1<<e_category::PortScan) | (1<<e_category::DoS);
	if (!check_rules(c, cset4, false, true, false, false, false)) ok = false; // Fits rule 2
	if (!c.class_match(0, cset4)) ok2 = false;

	unsigned int cset5 = (1<<e_category::SweepScan);
	if (!check_rules(c, cset5, true, false, false, false, false)) ok = false; // Fits rule 1
	if (!c.class_match(0, cset5)) ok2 = false;

	unsigned int cset6 = (1<<e_category::SweepScan) | (1<<e_category::DoS);
	if (!check_rules(c, cset6, false, false, false, false, false)) ok = false; // Fits no rule
	if (c.class_match(0, cset6) || c.class_match(1, cset6) || c.class_match(2, cset6)) ok2 = false;

	unsigned int cset7 = (1<<e_category::SweepScan) | (1<<e_category::PortScan) | (1<<e_category::DoS);
	if (!check_rules(c, cset7, false, false, false, false, false)) ok = false; // Fits no rule
	if (c.class_match(0, cset7) || c.class_match(1, cset7) || c.class_match(2, cset7)) ok2 = false;

	if (ok) cout << "* passed.\n"; else cout << "* failed.\n";

	cout << "\nSign set vs. class check:\n";
	if (ok2) cout << "* passed.\n"; else cout << "* failed.\n";


	cout << "\nAll done.\n\n";

	return 0;
}
#endif


//**************************************************************************************
// Test using a real sign set.
//**************************************************************************************

#ifdef UNIT_TEST2

int main()
{
	cout << "\nTEST 1: create set and add signs\n";
	cout <<   "********************************\n";

	C_Category C;
	C_Category::C_Category_set a;

	a.add(e_category::TRWscan);
	C.increment(a);
	a.clear();

	a.add(e_category::TRWscan);
	a.add(e_category::TRWnom);
	C.increment(a);
	a.clear();

	a.add(e_category::ICMP);
	a.add(e_category::OTHER);
	a.add(e_category::Unknown);
	C.increment(a);
	a.clear();

	a.add(e_category::Unknown);
	C.increment(a);
	a.clear();


	cout << "\nPer enum counts:\n";
	C.print_csv_header_cat();
	C.print_csv_data_cat();

	return 0;
}
#endif

