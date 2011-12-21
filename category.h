#ifndef CCATEGORY_H_
#define CCATEGORY_H_
/**
 *	\file category.h
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

#include <iostream>
#include <string>
#include <cstring>
#include <vector>

/**
 *	We enclose this enum type definitin with its own name to compnesate the C++
 *	deficiency of a missign enum type qualifier. Doing this we can avoid name
 *	conflicts.
 *	The purpose of this enum type is the naming of signs that can be attributed
 *	to a flow. Basically, every flow can be attributed a set of signs with an
 *	arbitrary size (minimal: empty set, maximal: all defined enum values).
 *
 *	We use two define statements to declare the names and the representing strings
 *	on top of each other to be able to print enum names for given enum values.
 *	This string print faeture is implemented in class C_Category::C_Category_set.
 */
namespace e_category {

// The defines must match! (there is no easy way in C++ to create string from enums)

#ifndef UNIT_TEST
#define category_enum_vals 		 TRWscan,TRWnom,HCscan,Backsc,GreyIP,bogon,P2P,Unreach,Retry,Onepkt,Artef,Large,PotOk,TCP,UDP,ICMP,OTHER,Unknown
#define category_enum_vals_str 	"TRWscan,TRWnom,HCscan,Backsc,GreyIP,bogon,P2P,Unreach,Retry,Onepkt,Artef,Large,PotOk,TCP,UDP,ICMP,OTHER,Unknown"

// For unit test: we must match enum code used in main() otherwise unit test code breaks
#else
#define category_enum_vals 		 SweepScan,PortScan,DoS,Unknown
#define category_enum_vals_str 	"SweepScan,PortScan,DoS,Unknown"
#endif

enum category_t {
	category_enum_vals
};
// By default enum values are zero-based

}// namespace

/**
 *	\class C_Category
 *	\brief This class supports the counting of arbitray sets of signs.
 *	For any set instance we maintain its own counter that is incremented
 *	every time when such a set instance is associated with a flow. This
 *	way we count the number of flows per distinct sign sets.
 *	The sign set as a fata type is implemented by inner class C_Category_set.
 */
class C_Category {

public:

	/**
	 *	\class C_Category_set
	 *	\brief This class implements a set of signs that can be associated with
	 *	a flow. For historical reasons we name such a sign set a category set.
	 */
	class C_Category_set {
	private:
		// Names of enum values as strings (for printing)
		std::vector<std::string> category_t_str;

		// Set of signs as a limited size bit set
		// (for a more general implementation type bitset might fit better)
		// Comment: the current implementation supports up to 32 signs.
		// Making use of the full set size would introduce 2**32 counters
		// in class C_Category (this does not scale anymore).
		unsigned int cset;

		// Count of unique defined enum values
		int ecnt;

		// Rules that define what signs must be present or absent
		// Each row represents one particular rule as follows:
		// Column 0: rule name
		// Column 1+: sign names
		// Note: row index represent rule number (bit position) important 
		// for accessing the mask arrays and the rule2class map.
		std::vector<std::vector<std::string> > rule_set;

		// Contains per rule a mask that contains 1-bits for signs that must be 
		// <<present>> in a sign set to match the rule.
		std::vector<unsigned int> mask_arr1;

		// Contains per rule a mask that contains 1-bits for signs that must be 
		// <<absent>> in a sign set to match the rule.
		std::vector<unsigned int> mask_arr2;

		// List of all classes names to assign a number (index) to each
		std::vector<std::string> class_names;

		// Rules-to-classes mappings: index is a rule number, entry is a class number
		// (class number can be used as index to classes_names)
		std::vector<int> rule2class_map;

	public:
		C_Category_set(unsigned int c = 0);

		// Add a sign to set.
		void add(e_category::category_t c) {
			cset |= (1 << c);
		}

		// Check if a sign is a member of the set.
		bool is_member(e_category::category_t c) {
			return (cset & (1 << c));
		}

		// Show bitset in hexadecimal represenation on console.
		void show() {
			std::cout << std::hex << "0x" << cset << std::dec << std::endl;
		}

		// Print all names of enum type values to console (or a given stream)
		void print(std::ostream & outfs = std::cout);

		// Output a newline to console
		void printnl() {
			print();
			std::cout << std::endl;
		}

		// Initialize sign set uing a given bit set.
		void set(unsigned int c) {
			cset = c;
		}

		// Get current sign set as a bit set.
		unsigned int get_set() {
			return cset;
		}

		// Read a set of rules from a text file. Every rule defines which signs
		// must be present or absent in a given set to match the rule.
		bool get_rules(std::string & rules_filename);

		// Show current settings of bitmasks.
		void show_masks();

		// Get count of unique enum values
		int get_enum_count() {
			return ecnt;
		}

		// Returns the internal reference number of a rule with a given name.
		// This number is needed to invoke "rule_match()" on the correct rule.
		int get_rule_number(std::string & rule_name);

		// Get total count of rules.
		int get_rule_count() {
			return rule_set.size();
		}

		// Get rule name string for a given rule number.
		bool get_rule_name(size_t rule_num, std::string & rule_name);

		// Checks if a given sign set matches a particular rule whose number is given
		bool rule_match(size_t rule_num, unsigned int cset);

		// Make sign set empty
		void clear() {
			cset = 0;
		}

	private:
		// Initialize bit masks from loaded rules
		void load_bitmasks();

		// Get numeric value for a given enum value name
		int get_enum_by_name(std::string & sign_name);

	};

	/**
	 *	\class C_Category_rc_signs
	 *	\brief Implements sign per rule or class accounting.
	 */
	class C_Category_rc_signs {
	private:
		std::vector<long long *> rc_signs; ///< Per rule or class sign count arrays
		int enum_count; ///< Count of distinct sign enum values
		int rc_count; ///< Rule or class count

	public:
		C_Category_rc_signs();
		void init(int enum_count, int rc_count);
		~C_Category_rc_signs();

		void reset();

		// Increment enum counters for given rule or class number
		void increment(int rc_number, unsigned int cset);

		// Write enum (flow) counts for given rule or class number to csv file
		void write_csv(std::ofstream * outfs, int rc_number);

		// Write enum (flow) counts for given rule or class number to csv file
		// (Use fraction of all one-way flows)
		void write_csv(std::ofstream * outfs, int rc_number, uint32_t flows);

		int get_rc_count() {
			return rc_count;
		}
	};

private:
	long long * ccounters; // Counter array for all categories and any possible combination of them
	long long * ecounters; // Counter per enum value (ignoring combinations)
	int num_counters;
	int num_enums;

public:
	C_Category();
	~C_Category();

	void increment(C_Category_set combi);

	void print_counters();
	void print_counters_full();

	void clear();
};

#endif

