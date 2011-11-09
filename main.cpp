/*
 * main.cpp
 *
 *  Created on: Oct 1, 2011
 *      Author: Nicolas Bigler
 */
#include <cstring>
#include <string>
#include <iomanip>
#include <functional>

#include <pcap++.h>

// Library functions, e.g. ntoh()
#include <arpa/inet.h>
#include <sys/stat.h>

// Protocol header definitions
#include <linux/if_ether.h>	// Ethernet header, ethernet protocol types
#include <netinet/ip.h>			// IP header
#include <netinet/tcp.h>		// TCP header
#include <netinet/udp.h>		// UDP header
#include <netinet/ip_icmp.h>	// ICMP header
#include <netinet/in.h>			// IP protocol types

// Boost includes
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/copy.hpp>
#include <fstream>


// Util
#include "libs/HashMap.h"
#include "libs/utils.h"
#include "libs/packet.h"
#include "libs/flowlist.h"
#include "CPersist.h"



bool debug = false;
unsigned long usflows = 0;
unsigned long sflows = 0;
unsigned long totalflows = 0;
unsigned long doubleflows = 0;

using namespace std;
using namespace pcappp;

// Hash key & map for storing flows
// ********************************
// key = 6-tuple (5-tuple + direction)
// data = references to flowlist records
//
typedef HashKeyIPv4_6T FlowHashKey6;
typedef HashKeyIPv4_7T PacketHashKey7;

uint8_t get_tcp_flags(tcphdr const &tcp_hdr);

/**
  *	Count flows by several criteria to provide basic statistics.
  *
  *	\param	fl Flowlist
  */
void count_flows(CFlowlist * fl)
{
	int flowcount = 0;
	int tcp_flowcount = 0;
	int udp_flowcount = 0;
	int icmp_flowcount = 0;
	int other_flowcount = 0;

	struct cflow * pflow = fl->get_first_flow();
	while (pflow != NULL) {
		flowcount++;
		switch (pflow->prot) {
			case IPPROTO_TCP:
				tcp_flowcount++;
				break;
			case IPPROTO_UDP:
				udp_flowcount++;
				break;
			case IPPROTO_ICMP:
				icmp_flowcount++;
				break;
			default:
				other_flowcount++;
				break;
		}

		pflow = fl->get_next_flow();
	}

	if(debug) {
		cout << flowcount << " flows read (TCP: " << tcp_flowcount << ", UDP: " << udp_flowcount;
		cout << ", ICMP: " << icmp_flowcount << ", OTHER: " << other_flowcount << ")\n";
	}
}


void print_statistics(int & signedf, int unsignedf, int & outflows, int & outflows_signed, int & biflows, int & biflows_signed, int & inflows, int & inflows_signed, int tcp_ok, int tcp_nok, int udp_ok, int udp_nok, int icmp_ok, int icmp_nok, int other_ok, int other_nok)
{
    // Show result statistics
    cout << "\nsigned (unsigned): " << signedf << " (" << unsignedf << ")\n";
    cout << "outflows (signed): " << outflows << " (" << outflows_signed << ")\n";
    cout << "biflows (signed): " << biflows << " (" << biflows_signed << ")\n";
    cout << "inflows (signed): " << inflows << " (" << inflows_signed << ")\n";
    cout << "TCP ok (nok):   " << tcp_ok << " (" << tcp_nok << ")\n";
    cout << "UDP ok (nok):   " << udp_ok << " (" << udp_nok << ")\n";
    cout << "ICMP ok (nok):  " << icmp_ok << " (" << icmp_nok << ")\n";
    cout << "OTHER ok (nok): " << other_ok << " (" << other_nok << ")\n\n";
}

void count_ok_nok(uint8_t prot, C_Category::C_Category_set cats, int & tcp_ok, int & tcp_nok, int & udp_ok, int & udp_nok, int & icmp_ok, int & icmp_nok, int & other_ok, int & other_nok)
{
    if (prot==IPPROTO_TCP) {
					if (cats.is_member(e_category::TCP)) { tcp_ok++; } else { tcp_nok++; }
				} else if (prot==IPPROTO_UDP) {
					if (cats.is_member(e_category::UDP)) { udp_ok++; } else { udp_nok++; }
				} else if (prot==IPPROTO_ICMP) {
					if (cats.is_member(e_category::ICMP)) { icmp_ok++; } else { icmp_nok++; }
				} else {
					if (cats.is_member(e_category::OTHER)) { other_ok++; } else { other_nok++; }
				}
}

bool sanity_check(CFlowlist * fl, uint32_t * fl_ref, bool use_outflows)
{
	cout << "\nDoing sanity checks on flow and sign data\n";
	cout << "*****************************************\n";
	int outflows = 0;
	int biflows  = 0;
	int inflows  = 0;

	int outflows_signed = 0;
	int biflows_signed  = 0;
	int inflows_signed  = 0;

	int signedf = 0;
	int unsignedf = 0;

	int tcp_ok  = 0;
	int tcp_nok = 0;
	int udp_ok  = 0;
	int udp_nok = 0;
	int icmp_ok  = 0;
	int icmp_nok = 0;
	int other_ok  = 0;
	int other_nok = 0;

	// Loop over all flows/sign sets
	struct  cflow * pflow = fl->get_first_flow();
	int i = 0;
	while (pflow != NULL) {
		uint8_t dir = pflow->dir;
		if (fl_ref[i] != 0) {
			signedf++;
		} else {
			unsignedf++;
		}
		if ((dir & outflow) != 0) {
			outflows++;
			if (fl_ref[i]!=0) outflows_signed++;
			if (use_outflows) {
				C_Category::C_Category_set cats;
				unsigned int cset = fl_ref[i];
				cats.set(cset);

				uint8_t prot = pflow->prot;
    count_ok_nok(prot, cats, tcp_ok, tcp_nok, udp_ok, udp_nok, icmp_ok, icmp_nok, other_ok, other_nok);

				if ((i % 100000) == 0) { cout << "."; cout.flush(); }
			}
		}
		if ((dir & biflow) != 0) {
			biflows++;
			if (fl_ref[i]!=0) biflows_signed++;
		}
		if ((dir & inflow) != 0) {
			inflows++;
			if (fl_ref[i]!=0) inflows_signed++;

			if (!use_outflows) {
				C_Category::C_Category_set cats;
				unsigned int cset = fl_ref[i];
				cats.set(cset);

				uint8_t prot = pflow->prot;
    count_ok_nok(prot, cats, tcp_ok, tcp_nok, udp_ok, udp_nok, icmp_ok, icmp_nok, other_ok, other_nok);

				if ((i % 100000) == 0) { cout << "."; cout.flush(); }
			}
		}
		pflow = fl->get_next_flow();
		i++;
	}

    print_statistics(signedf, unsignedf, outflows, outflows_signed, biflows, biflows_signed, inflows, inflows_signed, tcp_ok, tcp_nok, udp_ok, udp_nok, icmp_ok, icmp_nok, other_ok, other_nok);

	// Check if results are as expected

	bool error = false;
	if (outflows==0 || biflows==0 || inflows==0) error = true;
	if (!use_outflows) {
		if (outflows_signed!=0 || biflows_signed!=0 || inflows_signed==0) error = true;
		if (signedf != inflows_signed) error = true;
	} else {
		if (inflows_signed!=0 || biflows_signed!=0 || outflows_signed==0) error = true;
		if (signedf != outflows_signed) error = true;
	}
	if(error) {
		cout << "ERROR: test failed.\n";
		exit(-1);
	}

	cout << "Test passed successfully.\n";
	return error;
}


/**
  *	Classifies flows by applying rules and rule-to-class assocciations to actual
  *	sign sets of given flows. For each rule/class a flow matches the assigned
  *	counter is incremented. After all flows have been processed overall count
  *	values are written as new lines to statistics CSV files.
  *
  *
  *	\param	fl			Flowlist
  *	\param	fl_ref	List of sign sets aligned with fl
  *	\param	data		Persistent statistics variables needed for overall statistics.
  *	\param	inum		Number of currenr interval
  */
void process_rules(CFlowlist * fl, uint32_t * fl_ref, CPersist & data, int inum)
{
	// 1. Initialize
	// *************
	int rule_count = data.c.get_rule_count();
	if (rule_count == 0) {
		return;
	}
	uint32_t total_flows = 0;
	uint32_t total_packets = 0;
	uint64_t total_bytes = 0;

	/*for (int i = 0; i <= rule_count; i++) {
		data.flows[i] = 0;
		data.packets[i] = 0;
		data.bytes[i] = 0;
	}*/


	if (data.verbose) {
		cout << "\n*** Applying rules/class definitions to sign sets\n";
	}

	data.c.clear();

	// 2. Classify Flows
	// *****************
	// Check every flow against all rules and rule-to-class associations

	// Maintain a counter per rule
	int * flow_per_rule_counter	= new int[rule_count];
	//cout << "Rule count: " << rule_count << endl;
	for (int j=0; j <= rule_count; j++) {
		flow_per_rule_counter[j] = 0;
		data.hashedFlowlist.push_back(new CFlowHashMap6());
		data.hashedPacketlist.push_back(new packetHashMap7());
	}

	// Loop over all sign sets (i.e. all flows)
	int i = 0;
	struct cflow * pflow = fl->get_first_flow();
	while (pflow != NULL) {
		totalflows++;
		if (fl_ref[i] != 0) { // Ignore empty sign sets
			sflows++;
			total_flows++;
			total_packets += pflow->dPkts;
			total_bytes   += pflow->dOctets;
			util::swap_endians(*pflow);
			// Check signs against all rules and increment counters for matching ones
			bool found = false;
			for (int j=0; j<rule_count; j++) { // j is rule index
				if (data.c.rule_match(j, fl_ref[i])) {
					flow_per_rule_counter[j]++;
					// Update sign set of current rule
					data.rc.increment(j, fl_ref[i]);
					/*data.flows[j]++;
					data.packets[j] += pflow->dPkts;
					data.bytes[j]   += pflow->dOctets;*/
					FlowHashKey6 flowkey(&(pflow->localIP),&(pflow->remoteIP),&(pflow->localPort),&(pflow->remotePort),&(pflow->prot),&(pflow->flowtype));

					CFlowHashMap6::iterator iter = (*data.hashedFlowlist[j]).find(flowkey);
					if ((*data.hashedFlowlist[j]).end() != iter){
						doubleflows++;
					}
					(*data.hashedFlowlist[j]).insert(CFlowHashMap6::value_type (flowkey, *pflow));
					found = true;
				}
			}
			if (found == false) {
				flow_per_rule_counter[rule_count]++;
				// Update sign set of current rule
				data.rc.increment(rule_count, fl_ref[i]);
				/*data.flows[rule_count]++;
				data.packets[rule_count] += pflow->dPkts;
				data.bytes[rule_count]   += pflow->dOctets;*/
				FlowHashKey6 flowkey(&(pflow->localIP),&(pflow->remoteIP),&(pflow->localPort),&(pflow->remotePort),&(pflow->prot),&(pflow->flowtype));
				CFlowHashMap6::iterator iter = (*data.hashedFlowlist[rule_count]).find(flowkey);
				if ((*data.hashedFlowlist[rule_count]).end() != iter){
					doubleflows++;
				}
				(*data.hashedFlowlist[rule_count]).insert(CFlowHashMap6::value_type (flowkey, *pflow));
			}
		}else {
			usflows++;
		}
		pflow = fl->get_next_flow();
		i++;
	}
}

int get_icmp_type(packet p) {
	return p.ipPayload.icmpHeader.type;
}

int get_icmp_code(packet p) {
	return p.ipPayload.icmpHeader.code;
}

bool valid_flag_sequence_check(const PacketHashKey7 &paketkey, CPersist &data, int rule_pos) {

	packetHashMap7::iterator iter = data.hashedPacketlist[rule_pos]->find(paketkey);

	int counter = 0;
	uint8_t flag_sequence[5] = {0x00, 0x00, 0x00, 0x00, 0x00};
	uint8_t tcp_flags;

	//Fill flag sequence with 5 first packets from flow
	if (iter != data.hashedPacketlist[rule_pos]->end()){
		for (vector<packet>::iterator it = (*iter).second.begin(); (it != (*iter).second.end()) && counter < 5; ++it){
			tcp_flags = get_tcp_flags((*it).ipPayload.tcpHeader);

			//cout << "Packet of flow: " << counter << endl;
			//cout << "Current Flag Sequence: " << tcp_flags << endl;

			flag_sequence[counter] = tcp_flags;
			counter++;
		}
	}
	//Check if flag sequence is valid
	if(flag_sequence[0] == 0x02 && flag_sequence[1] == 0x02 && flag_sequence[2] == 0x02 && flag_sequence[3] == 0x02 && flag_sequence[4] == 0x02) return true; // 5 syn flags
	if(flag_sequence[0] == 0x02 && flag_sequence[1] == 0x02 && flag_sequence[2] == 0x02 && flag_sequence[3] == 0x02 && flag_sequence[4] == 0x00) return true; // 4 syn flags
	if(flag_sequence[0] == 0x02 && flag_sequence[1] == 0x02 && flag_sequence[2] == 0x02 && flag_sequence[3] == 0x00 && flag_sequence[4] == 0x00) return true; // 3 syn flags
	if(flag_sequence[0] == 0x02 && flag_sequence[1] == 0x02 && flag_sequence[2] == 0x00 && flag_sequence[3] == 0x00 && flag_sequence[4] == 0x00) return true; // 2 syn flags
//	if(flag_sequence[0] == 0x02 && flag_sequence[1] == 0x00 && flag_sequence[2] == 0x00 && flag_sequence[3] == 0x00 && flag_sequence[4] == 0x00) return true; // 1 syn flag equals SYN Scan! -> Probably no benign TCP behavior

	return false;
}
void write_stats_fp(CPersist & data){
	ofstream out;

	string filename = "tcp_false_positives.csv";
	util::open_outfile(out, filename);
	out << "Class; Count" << endl;
	map<string, int>::iterator iter;
	for (iter = data.tcp_false_positives.begin(); iter != data.tcp_false_positives.end(); iter++){
		out << (*iter).first << ";" << (*iter).second << endl;
	}
	out.close();

	filename = "tcp_false_negatives.csv";
	util::open_outfile(out, filename);
	out << "Class; Count" << endl;
	for (iter = data.tcp_false_negatives.begin(); iter != data.tcp_false_negatives.end(); iter++){
		out << (*iter).first << ";" << (*iter).second << endl;
	}
	out.close();

	filename = "icmp_false_positives.csv";
	util::open_outfile(out, filename);
	out << "Class; Count" << endl;
	for (iter = data.icmp_false_positives.begin(); iter != data.icmp_false_positives.end(); iter++){
		out << (*iter).first << ";" << (*iter).second << endl;
	}
	out.close();
}

void write_aff_stats(CPersist & data){
	ofstream out;

	string filename = "scan5_aff_stats.csv";
	util::open_outfile(out, filename);
	out << "Aff; Count" << endl;
	map<string, int>::iterator iter;
	for (iter = data.scan5_aff_flow_count.begin(); iter != data.scan5_aff_flow_count.end(); iter++){
		out << (*iter).first << ";" << (*iter).second << endl;
	}
	out.close();

}

void get_tcp_false_positives(CPersist &data, bool verbose) {
	vector<int> false_positives;

//	int scan_false_positive = 0;
//	int malign_false_positive = 0;
//	int backscatter_false_positive = 0;
//TODO : What are the exact criteria for the categories below?
//	int unreachable_false_positive = 0;
	int p2p_false_positive = 0;
	int benign_false_positive = 0;

	false_positives.push_back(0);
	false_positives.push_back(0);
	false_positives.push_back(0);
	false_positives.push_back(0);

	bool false_positive_flow_found = false;
	for(int rule_no = 12; rule_no < 13; rule_no++) {
			for(packetHashMap7::iterator it = data.hashedPacketlist[rule_no]->begin(); it != data.hashedPacketlist[rule_no]->end(); ++it) {
				for(vector<packet>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
					if((*it2).protocol == IPPROTO_TCP) {
						if(!(valid_flag_sequence_check((*it).first, data, rule_no))) {
							false_positive_flow_found = true;
						}
					}
				}
				if (false_positive_flow_found){
					data.tcp_false_positives["BenignP2P"]++;
					if(verbose) {
						cout << "ICMP Flow found which doesn't belong to class P2P" << endl;
					}
					false_positive_flow_found = false;
				}
			}
	}


	for(int rule_no = 13; rule_no < 16; rule_no++) {
				for(packetHashMap7::iterator it = data.hashedPacketlist[rule_no]->begin(); it != data.hashedPacketlist[rule_no]->end(); ++it) {
					for(vector<packet>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
						if((*it2).protocol == IPPROTO_TCP) {
							if(!(valid_flag_sequence_check((*it).first, data, rule_no))) {
								false_positive_flow_found = true;
							}
						}
					}
					if (false_positive_flow_found){
						data.tcp_false_positives["SuspBenign"]++;
						if(verbose) {
							cout << "ICMP Flow found which doesn't belong to class Suspected Benign" << endl;
						}
						false_positive_flow_found = false;
					}
				}
		}
}

void get_tcp_false_negatives(CPersist &data, bool verbose) {
	vector<int> false_negatives;

		int scan_false_negative = 0;
		//TODO : What are the exact criteria for the categories below?
			//	int malign_false_negative = 0;
			//	int backscatter_false_negative = 0;
			//	int unreachable_false_negative = 0;
			//	int p2p_false_negative = 0;
			//	int benign_false_negative = 0;

		bool false_negative_flow_found = false;
		for(int rule_no = 0; rule_no <= data.c.get_rule_count(); rule_no++) {
			if(!(rule_no == 0 || rule_no == 1 || rule_no == 2 || rule_no == 3 || rule_no == 4)) { //For all classes except Scan
				for(packetHashMap7::iterator it = data.hashedPacketlist[rule_no]->begin(); it != data.hashedPacketlist[rule_no]->end(); ++it) {

					if((*(*it).second.begin()).protocol == IPPROTO_TCP) {
						//Stealth scans (Scans w/o preceding 3-way handshake)
						if(get_tcp_flags((*(*it).second.begin()).ipPayload.tcpHeader) == 0x29) { //X-Mas Tree Scan (URG+PSH+FIN)
							false_negative_flow_found = true;
							if(verbose) {
								cout << "False Negative: Flow assigned to Rule " << rule_no << " but is X-Mas Tree Scan" << endl;
							}
						}

						if(get_tcp_flags((*(*it).second.begin()).ipPayload.tcpHeader) == 0x01) { //FIN Scan
							false_negative_flow_found = true;
							if(verbose) {
								cout << "False Negative: Flow assigned to Rule " << rule_no << " but is FIN Scan" << endl;
							}
						}

						if(get_tcp_flags((*(*it).second.begin()).ipPayload.tcpHeader) == 0x00) { //Null Scan
							false_negative_flow_found = true;
							if(verbose) {
								cout << "False Negative: Flow assigned to Rule " << rule_no << " but is Null Scan" << endl;
							}
						}

						if(get_tcp_flags((*(*it).second.begin()).ipPayload.tcpHeader) == 0x02 && ++(*it).second.begin() == (*it).second.end()) { //SYN Scan
							false_negative_flow_found = true;
							if(verbose) {
								cout << "False Negative: Flow assigned to Rule " << rule_no << " but is SYN Scan" << endl;
							}
						}
					}
				}
			}
			if (false_negative_flow_found){
				data.tcp_false_negatives["MalScan"]++;
				if(verbose) {
					cout << "TCP Flow found which should belong to class scan" << endl;
				}
				false_negative_flow_found = false;
			}
		}
}

void get_icmp_false_positives(CPersist &data, bool verbose) {

	vector<int> false_positives;

	//TODO : What are the exact criteria for the categories below?
//	int unreachable_false_positive = 0;
//	int p2p_false_positive = 0;
//	int benign_false_positive = 0;

	//Check flows classified as scan for ICMP non-requests
	bool false_positive_flow_found = false;
	for(int rule_no = 0; rule_no < 5; rule_no++) {
			for(packetHashMap7::iterator it = data.hashedPacketlist[rule_no]->begin(); it != data.hashedPacketlist[rule_no]->end(); ++it) {
				for(vector<packet>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
					if((*it2).protocol == IPPROTO_ICMP) {
						if(!(get_icmp_type(*it2) == 8 || get_icmp_type(*it2) == 13 ||get_icmp_type(*it2) == 15 || get_icmp_type(*it2) == 17 || get_icmp_type(*it2) == 35|| get_icmp_type(*it2) == 37)) {
							false_positive_flow_found = true;
						}
					}
				}
				if (false_positive_flow_found){
					data.icmp_false_positives["MalScan"]++;
					if(verbose) {
						cout << "ICMP Flow found which doesn't belong to class scan" << endl;
					}
					false_positive_flow_found = false;
				}
			}
	}


	//Check flows classified as malign for ICMP packets
	for(int rule_no = 5; rule_no < 8; rule_no++) {
			for(packetHashMap7::iterator it = data.hashedPacketlist[rule_no]->begin(); it != data.hashedPacketlist[rule_no]->end(); ++it) {
				for(vector<packet>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
					if((*it2).protocol == IPPROTO_ICMP) {
						false_positive_flow_found = true;
					}
				}
				if(false_positive_flow_found) {
					data.icmp_false_positives["OtherMal"]++;
					if(verbose) {
						cout << "ICMP Flow found which doesn't belong to class malign" << endl;
					}
					false_positive_flow_found = false;
				}
			}
	}

	//Check flows classified as backscatter for requests (ICMP Type 8, ICMP Type 13 or ICMP Type 15, ...)
	for(int rule_no = 8; rule_no < 11; rule_no++) {
		for(packetHashMap7::iterator it = data.hashedPacketlist[rule_no]->begin(); it != data.hashedPacketlist[rule_no]->end(); ++it) {
			for(vector<packet>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
				if((*it2).protocol == IPPROTO_ICMP) {
					if(get_icmp_type(*it2) == 8 || get_icmp_type(*it2) == 13 || get_icmp_type(*it2) == 15 || get_icmp_type(*it2) == 17|| get_icmp_type(*it2) == 35|| get_icmp_type(*it2) == 37) {
						false_positive_flow_found = true;
					}
				}
			}
			if (false_positive_flow_found) {
				data.icmp_false_positives["Backscat"]++;
				if(verbose) {
					cout << "ICMP Packet found which doesn't belong to class backscatter" << endl;
				}
				false_positive_flow_found = false;
			}
		}
	}
}

void get_stats(CPersist &data) {
	for (int i=0; i <= data.c.get_rule_count(); i++){

        for(packetHashMap7::iterator it = data.hashedPacketlist[i]->begin(); it != data.hashedPacketlist[i]->end(); ++it) {
			if (((*it).second.begin()->protocol == IPPROTO_TCP) || ((*it).second.begin()->protocol == IPPROTO_UDP)){
					++data.portlist_local[(*it).second[0].localPort];
					++data.portlist_remote[(*it).second[0].remotePort];
			}
			if ((*it).second.begin()->protocol == IPPROTO_ICMP){
					++data.itc[get_icmp_type((*it).second[0])][get_icmp_code((*it).second[0])];
			}
        }

	}
}

void get_affirmative_flow_count(CPersist & data, bool verbose){
	// Scan 5
	int rule_no = 4;
	for(packetHashMap7::iterator it = data.hashedPacketlist[rule_no]->begin(); it != data.hashedPacketlist[rule_no]->end(); ++it) {

		if((*(*it).second.begin()).protocol == IPPROTO_TCP) {
			//Stealth scans (Scans w/o preceding 3-way handshake)
			if(get_tcp_flags((*(*it).second.begin()).ipPayload.tcpHeader) == 0x29) { //X-Mas Tree Scan (URG+PSH+FIN)
				data.scan5_aff_flow_count["1"]++;
				if(verbose) {
					cout << "False Negative: Flow assigned to Rule " << rule_no << " but is X-Mas Tree Scan" << endl;
				}
			}else if(get_tcp_flags((*(*it).second.begin()).ipPayload.tcpHeader) == 0x01) { //FIN Scan
				data.scan5_aff_flow_count["1"]++;
				if(verbose) {
					cout << "False Negative: Flow assigned to Rule " << rule_no << " but is FIN Scan" << endl;
				}
			}else if(get_tcp_flags((*(*it).second.begin()).ipPayload.tcpHeader) == 0x00) { //Null Scan
				data.scan5_aff_flow_count["1"]++;
				if(verbose) {
					cout << "False Negative: Flow assigned to Rule " << rule_no << " but is Null Scan" << endl;
				}
			}else if(get_tcp_flags((*(*it).second.begin()).ipPayload.tcpHeader) == 0x02 && ++(*it).second.begin() == (*it).second.end()) { //SYN Scan
				data.scan5_aff_flow_count["1"]++;
				if(verbose) {
					cout << "False Negative: Flow assigned to Rule " << rule_no << " but is SYN Scan" << endl;
				}
			}else{
				data.scan5_aff_flow_count["0"]++;
			}
		}else if((*(*it).second.begin()).protocol == IPPROTO_UDP) {
			if ((*(*it).second.begin()).ipPayload.actualsize == (*(*it).second.begin()).ipPayload.packetsize){
				// UDP Packet has no payload
				data.scan5_aff_flow_count["3"]++;
			}else {
				data.scan5_aff_flow_count["2"]++;
			}
		}
	}
}


void get_flow_count(CPersist &data){
	ofstream out;
	string statfile_flowcount = "flowcount.csv";
	util::open_outfile(out, statfile_flowcount);
	out << "Rule; Count" << endl;
	long total_rflows = 0;
	for (int i=0; i <= data.c.get_rule_count(); i++){
		int flowcount = 0;
		cout << "Rule: " << i << endl;
		for (CFlowHashMap6::iterator it = data.hashedFlowlist[i]->begin(); it != data.hashedFlowlist[i]->end(); it++){
			++flowcount;
		}
		string rulename;
		data.c.get_rule_name(i, rulename);
		out << rulename << ";" << flowcount << endl;
		total_rflows += flowcount;
	}

	out.close();
	cout << "Total Flows in all rules: " << total_rflows << endl;
	cout << "--------------" << endl;
	cout << "Total Flows with same key: " << doubleflows << endl;
	cout << "Total Flows with signes: " << sflows << endl;
	cout << "Total Flows without signes: " << usflows << endl;
	cout << "Total Flows: " << totalflows << endl;
}

void print_stats(CPersist & data, string filename){
	string statfile_icmp = "icmp_" + filename.substr(0,filename.find(".pcap")) + ".csv";
	string statfile_ports = "ports_" + filename.substr(0,filename.find(".pcap")) + ".csv";
	ofstream out;
	util::open_outfile(out, statfile_icmp);
	out << "Type; Code; Count" << endl;
	for (int i = 0; i < data.TYPE_COUNT; i++){
			for (int j = 0; j < data.CODE_COUNT; j++){
					if (data.itc[i][j] > 0){
							out << i << ";" << j << ";" << data.itc[i][j] << endl;
					}
			}
	}
	out.close();
	util::open_outfile(out, statfile_ports);
	out << "Port; Port; Local Count; Remote Count" << endl;
	for (int i=0; i < data.PORT_COUNT; i++){
			out << i << ";" << data.portlist_local[i] << ";" << data.portlist_remote[i] << endl;
	}

}
void check_file_status(string & sign_filename)
{
    struct stat fileStatus;
    int iretStat = stat(sign_filename.c_str(), &fileStatus);
    if(iretStat == -1){
        cerr << "\nERROR: " << sign_filename << " does not exist or is not accessible.\n";
        perror("stat()");
        cerr << "Check file name.\n\n";
        char buf[256];
        getcwd(buf, 256);
        cout << "Current working directory is: " << buf << endl;
        exit(1);
    }
}

void select_flow_direction(bool & use_outflows, string & sign_filename, string basename)
{
    if(!use_outflows){
        sign_filename = basename + ".sig.gz";
    }else{
        sign_filename = basename + "_O.sig.gz";
    }
}

uint32_t *read_per_flow_sign_sets(string & filename, bool & use_outflows, int flow_count)
{
    // 2. Get per-flow sign sets
    // *************************
    string basename = filename.substr(0, filename.find(".gz"));
    string sign_filename;
    select_flow_direction(use_outflows, sign_filename, basename);
    check_file_status(sign_filename);
    // Read per-flow sign sets to memory, i.e., array "fl_ref".
    uint32_t *fl_ref = new uint32_t[flow_count];
    // Open up a stream chain
    boost::iostreams::filtering_istream in;
    // Add stream compressor
    in.push(boost::iostreams::gzip_decompressor());
    // Open input file and link it to stream chain
    boost::iostreams::file_source infs(sign_filename);
    if(!infs.is_open()){
        cerr << "ERROR: could not open file source \"" << sign_filename << "\".\n";
        exit(1);
    }
    in.push(infs);
    // Now get all sign sets
    in.read((char*)(((fl_ref))), flow_count * sizeof (uint32_t));
    //cout << "\nRead " << in.gcount() / 2 << " values from sig file " << sign_filename << endl;
    // Close current input file (and stream compressor)
    in.pop();
    return fl_ref;
}

/**
  *	Process flow and sign data from one time interval.
  *
  *	\param filename	  Name of flow data inoput file (name of sign file is derived from this name)
  *	\param data         Cross-interval data (e.g. counters and output streams)
  *	\param inum         Interval number (first interval must have inum=0)
  *	\param use_outflows TRUE when outflows should be classified instead of inflows
  *
  *	\return TRUE if processing successful, FALSE otherwise
  */
bool process_interval(string & filename, CPersist & data, int inum, bool use_outflows)
{
	CFlowlist * fl = new CFlowlist(filename);
	fl->read_flows();

	// Show some basic statistics on flow data read
	if (data.test) count_flows(fl);

	int flow_count = fl->get_flow_count();
	if (data.verbose) cout << endl << flow_count << " flows read from file " << filename << endl;


    uint32_t *fl_ref = read_per_flow_sign_sets(filename, use_outflows, flow_count);

	if (data.test) {
		sanity_check(fl, fl_ref, use_outflows);
	}

	process_rules(fl, fl_ref, data, inum);

	delete[] fl_ref;
	delete fl;
	return true;
}

void usage(char * progname, ostream & outfs)
{
	outfs << "\nEvaluates signs assigned to one-way flows. One or more file names \n";
	outfs << "of flow data files are expected. To specify more than one input file name\n";
	outfs << "use option -f and a file containing a list of file names.\n";
	outfs << "Unless option -d is used an input file name *YYYYMMDD.hhmm.gz is expected.\n";

	outfs << "Usage: " << progname << " [options] [pcap_file] [input_filename]\n\n";

	outfs << "Options:\n";
	outfs << "-f <filename>  File containing list of input file names (default: [use input_filename]).\n";
	outfs << "-r <filename>  Create sign statistics by rules stored in <filename> (default: none)\n";
	outfs << "-c <filename>  Create sign statistics by classes stored in <filename> (default: none)\n";
	outfs << "-p <filename>  pcap file of the flow data corresponding to the flows in *.gz files\n";
	outfs << "-t             Run sanity checks only.\n";
	outfs << "-O             Classify ouflows instead of inflows.\n";
	outfs << "-d <date>      Date of form YYYYMMDD to be used in file naming (default: extracted from file name).\n";
	outfs << "-h             Show help info.\n";
	outfs << "-v             Show additional informative messages.\n";

	outfs << endl;
}


void find_match(packet &p, CFlowHashMap6* hashedFlowMap, CPersist & data, int rule_pos, bool use_outflows){
	if (use_outflows){
		uint8_t out = outflow;
        uint8_t q_out = q_outfl;

		FlowHashKey6 mykey(&(p.remoteIP), &(p.localIP), &(p.remotePort),
						&(p.localPort), &(p.protocol), &(out));
		FlowHashKey6 mykey_q(&(p.remoteIP), &(p.localIP), &(p.remotePort),
						&(p.localPort), &(p.protocol), &(q_out));

		CFlowHashMap6::iterator iter;

		pair<CFlowHashMap6::iterator,CFlowHashMap6::iterator > cf_range;
		pair<CFlowHashMap6::iterator,CFlowHashMap6::iterator > cf_range_q;

		cf_range = hashedFlowMap->equal_range(mykey);
		cf_range_q = hashedFlowMap->equal_range(mykey);

		for (iter = cf_range.first; iter != cf_range.second; ++iter){
			if (((*iter).second.startMs <= p.ipPayload.timestamp/1000) && (p.ipPayload.timestamp/1000 <= ((*iter).second.startMs+(*iter).second.durationMs))){
				uint64_t packetTime = p.ipPayload.timestamp/1000;
				PacketHashKey7 pkey(&(p.remoteIP), &(p.localIP), &(p.remotePort),
							&(p.localPort), &(p.protocol), &(out), &(packetTime));
				(*data.hashedPacketlist[rule_pos])[pkey].push_back(p);
			}

		}
		for (iter = cf_range_q.first; iter != cf_range_q.second; ++iter){
			if (((*iter).second.startMs <= p.ipPayload.timestamp/1000) && (p.ipPayload.timestamp/1000 <= ((*iter).second.startMs+(*iter).second.durationMs))){
				uint64_t packetTime = p.ipPayload.timestamp/1000;
				PacketHashKey7 pkey(&(p.remoteIP), &(p.localIP), &(p.remotePort),
						&(p.localPort), &(p.protocol), &(q_out), &(packetTime));
				(*data.hashedPacketlist[rule_pos])[pkey].push_back(p);
			}

		}
	}else{
		uint8_t in = inflow;
        uint8_t q_in = q_infl;


		FlowHashKey6 mykey(&(p.remoteIP), &(p.localIP), &(p.remotePort),
                        &(p.localPort), &(p.protocol), &(in));
        FlowHashKey6 mykey_q(&(p.remoteIP), &(p.localIP), &(p.remotePort),
                        &(p.localPort), &(p.protocol), &(q_in));

        CFlowHashMap6::iterator iter;

        pair<CFlowHashMap6::iterator,CFlowHashMap6::iterator > cf_range;

        cf_range = hashedFlowMap->equal_range(mykey);

        for (iter = cf_range.first; iter != cf_range.second; ++iter){
        	if (((*iter).second.startMs <= p.ipPayload.timestamp/1000) && (p.ipPayload.timestamp/1000 <= ((*iter).second.startMs+(*iter).second.durationMs))){
        		uint64_t packetTime = p.ipPayload.timestamp/1000;
        		PacketHashKey7 pkey(&(p.remoteIP), &(p.localIP), &(p.remotePort),
							&(p.localPort), &(p.protocol), &(in), &(packetTime));
				(*data.hashedPacketlist[rule_pos])[pkey].push_back(p);
        	}

        }

        cf_range = hashedFlowMap->equal_range(mykey_q);
        for (iter = cf_range.first; iter != cf_range.second; ++iter){
        	if (((*iter).second.startMs <= p.ipPayload.timestamp/1000) && (p.ipPayload.timestamp/1000 <= ((*iter).second.startMs+(*iter).second.durationMs))){
        		uint64_t packetTime = p.ipPayload.timestamp/1000;
        		PacketHashKey7 pkey(&(p.remoteIP), &(p.localIP), &(p.remotePort),
						&(p.localPort), &(p.protocol), &(q_in), &(packetTime));
				(*data.hashedPacketlist[rule_pos])[pkey].push_back(p);
        	}

        }
	}


//	typedef pair<HashKeyIPv4_6T, packet> hash_pair;
}
void process_pcap(string pcap_filename, CPersist & data, bool use_outflows)
{
    struct packet packet;
    memset((void*)(&packet), 0, sizeof (packet));

    // Open file for packet reading
    int pcount = 0; // Packet counter
    try {
		PcapOffline pco(pcap_filename);
		string filename = pco.get_filename();

		DataLink dl = pco.get_datalink();

		// Process saved packets
		// *********************
		// Loop through pcap file by reading packet-by-packet.
		Packet p;
		while (pco.ok()) {
			//flow = {0};
			memset(&packet, 0, sizeof(packet));

			// Get next packet from file
			if (!pco.next(p)) break;	// Quit if no more packets avaliable
			pcount++;

			// Get packet length from header, but limit it to capture length
			Packet::Length len = (p.get_length() > p.get_capture_length()) ? p.get_length() : p.get_capture_length();

			if (len < sizeof(struct ethhdr)) { // Is packet too small?
				cerr << "Found malformed packet.\n"; continue;
			}

			Packet::Data const * pdata = p.get_data();

			struct ethhdr * ether_hdr = (struct ethhdr *)pdata;

			if (debug) {
				cout << pcount << ": ethertype = 0x";
				char prev = cout.fill('0');
				streamsize oldwidth = cout.width(4);
				cout << hex << ntohs(ether_hdr->h_proto) << dec << endl;
				cout.fill(prev);
				cout.width(oldwidth);
			}
			// Display packet header data if data link protocol is ethernet
			if (ntohs(ether_hdr->h_proto) == ETH_P_IP) {	// Check if IPv4 packet

				// Process IPv4 packet
				// *******************

				if (len < (sizeof(struct ethhdr)+sizeof(struct iphdr)  )) { // Is packet too small?
					cerr << "Found malformed packet.\n"; continue;
				}
				struct iphdr * ip_hdr = (struct iphdr *)(pdata+sizeof(struct ethhdr));

				struct tcphdr * tcp_hdr = NULL;
				struct udphdr * udp_hdr = NULL;
				struct icmphdr * icmp_hdr = NULL;

				uint32_t netmask;
				inet_pton(AF_INET, "152.103.0.0", &netmask);
				// Show transport layer protocol
				/*if ((ip_hdr->saddr&netmask) == netmask){
					packet.init(ip_hdr->saddr, ip_hdr->daddr, ip_hdr->protocol, outflow);
				}else{
					packet.init(ip_hdr->daddr, ip_hdr->saddr, ip_hdr->protocol, inflow);
				}*/
				packet.init(ip_hdr->saddr, ip_hdr->daddr, ip_hdr->protocol);
				//packet.tos_flags = ip_hdr->tos;
				//packet.ethHeader = *ether_hdr;
				//packet.ipHeader = *ip_hdr;
				switch (ip_hdr->protocol) {
				case IPPROTO_TCP:
					tcp_hdr = (struct tcphdr *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					packet.localPort = ntohs(tcp_hdr->source);
					packet.remotePort = ntohs(tcp_hdr->dest);
					packet.ipPayload.tcpHeader = *tcp_hdr;
					//packet.ipPayload.packetsize = (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr));
					//packet.ipPayload.payloadsize = p.get_capture_length() - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr));
					//(*packet.ipPayload.payload) = (*pdata+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr));
					break;
				case IPPROTO_UDP:
					udp_hdr = (struct udphdr *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					packet.localPort = ntohs(udp_hdr->source);
					packet.remotePort = ntohs(udp_hdr->dest);
					packet.ipPayload.udpHeader = *udp_hdr;
					//packet.ipPayload.packetsize = (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr));
					//packet.ipPayload.payloadsize = p.get_capture_length() - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr));
					//(*packet.ipPayload.payload) = (*pdata+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr));
					break;
				case IPPROTO_ICMP:
					icmp_hdr = (struct icmphdr *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					packet.ipPayload.icmpHeader = *icmp_hdr;
					//packet.ipPayload.packetsize = (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr));
					//packet.ipPayload.payloadsize = p.get_capture_length() - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr));
					//(*packet.ipPayload.payload) = (*pdata+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr));
					break;
				default:
					//packet.ipPayload.packetsize = (sizeof(struct ethhdr)+sizeof(struct iphdr));
					//packet.ipPayload.payloadsize = p.get_capture_length() - (sizeof(struct ethhdr)+sizeof(struct iphdr));
					//(*packet.ipPayload.payload) = (*pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					break;
				}
				packet.ipPayload.timestamp = p.get_seconds()*1000000 + p.get_miliseconds();
				packet.ipPayload.packetsize = p.get_capture_length();
				packet.ipPayload.actualsize = p.get_length();

				for (int i = 0; i <= data.c.get_rule_count(); i++){
					//cout << "---------------Rule position: " << i << "-----------------" << endl;
					find_match(packet, data.hashedFlowlist[i], data, i, use_outflows);
				}

			}
		}

	} catch (PcapError & pcerror) {

		cerr << "ERROR: " << pcerror.what() << endl;

	} catch (...) {
		cout << "ERROR: unknown exception occurred.\n";
	}
}


void write_pcap(CPersist & data, bool use_outflows){


	struct pcapFileHeader {
	    uint32_t magic_number;   /* magic number */
	    uint16_t version_major;  /* major version number */
	    uint16_t version_minor;  /* minor version number */
	    int16_t  thiszone;       /* GMT to local correction */
	    uint32_t sigfigs;        /* accuracy of timestamps */
	    uint32_t snaplen;        /* max length of captured packets, in octets */
	    uint32_t network;        /* data link type */

	    pcapFileHeader (uint32_t magic, uint16_t major, uint16_t minor,
	    		int16_t zone, uint32_t ts_acc, uint32_t max_packlen, uint32_t dl_type){
	    	magic_number = magic;
	    	version_major = major;
	    	version_minor = minor;
	    	thiszone = zone;
	    	sigfigs = ts_acc;
	    	snaplen = max_packlen;
	    	network = dl_type;
	    }
	};

	struct pcapPacketHeader {
	    uint32_t ts_sec;         /* timestamp seconds */
	    uint32_t ts_usec;        /* timestamp microseconds */
	    uint32_t incl_len;       /* number of octets of packet saved in file */
	    uint32_t orig_len;       /* actual length of packet */

	    void init (uint64_t timestamp, uint32_t packetsize, uint32_t actualsize) {
	    	ts_sec = timestamp/1000000;
	    	ts_usec = timestamp%1000000;
	    	incl_len = packetsize;
	    	orig_len = actualsize;
	    }
	};

	pcapFileHeader fileHeader(0xa1b2c3d4, 2, 4, 0, 0, 65535, 1);

	pcapPacketHeader packetHeader;
	ofstream fileout;
	string rulename;
	string filename;



	for (int i=0; i <= data.c.get_rule_count(); i++){
		if (i == data.c.get_rule_count()){
			rulename = "Other";
		}else {
			data.c.get_rule_name(i, rulename);
		}
		if (use_outflows){
			filename = "rule_" + rulename + "_" + data.date + "_O.pcap";
		}else{
			filename = "rule_" + rulename + "_" + data.date + ".pcap";
		}
		if (fopen(filename.c_str(),"r")==0){
			fileout.open(filename.c_str(), ios::trunc | ios::binary);
			fileout.write(reinterpret_cast<const char*>(&fileHeader),
							  sizeof fileHeader);
		}else{
			fileout.open(filename.c_str(), ios::app | ios::binary);
		}
		packetHashMap7::iterator iter;
		vector<packet>::iterator it;
		for (iter = data.hashedPacketlist[i]->begin(); iter != data.hashedPacketlist[i]->end(); iter++){
			for (it = (*iter).second.begin(); it != (*iter).second.end(); ++it){
				//packetHeader.init(it->ipPayload.timestamp, it->ipPayload.packetsize, it->ipPayload.actualsize);
				fileout.write(reinterpret_cast<const char*>(&packetHeader), sizeof fileHeader);
				//fileout.write(reinterpret_cast<const char*>(&it->ethHeader), sizeof(struct ethhdr));
				//fileout.write(reinterpret_cast<const char*>(&it->ipHeader), sizeof(struct iphdr));

				switch (it->protocol) {
					case IPPROTO_TCP:
						fileout.write(reinterpret_cast<const char*>(&it->ipPayload.tcpHeader), sizeof(struct tcphdr));
						//fileout.write(reinterpret_cast<const char*>(&it->ipPayload.payload), it->ipPayload.packetsize - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr)));
						break;
					case IPPROTO_UDP:
						fileout.write(reinterpret_cast<const char*>(&it->ipPayload.udpHeader), sizeof(struct udphdr));
						//fileout.write(reinterpret_cast<const char*>(&it->ipPayload.payload), it->ipPayload.packetsize - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)));
						break;
					case IPPROTO_ICMP:
						fileout.write(reinterpret_cast<const char*>(&it->ipPayload.icmpHeader), sizeof(struct icmphdr));
						//fileout.write(reinterpret_cast<const char*>(&it->ipPayload.payload), it->ipPayload.packetsize - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr)));
						break;
					default:
						//fileout.write(reinterpret_cast<const char*>(&it->ipPayload.payload), it->ipPayload.packetsize - (sizeof(struct ethhdr)+sizeof(struct iphdr)));
						break;
				}
			}
		}
		fileout.close();
	}

}

void clear_stats_variables(CPersist & data){
	for (int i = 0; i<= data.TYPE_COUNT; i++){
		for (int j = 0; j <= data.CODE_COUNT; j++){
			data.itc[i][j] = 0;
		}
	}

	for (int k = 0; k<= data.PORT_COUNT; k++){
		data.portlist_local[k] = 0;
		data.portlist_remote[k] = 0;
	}
}
void clear_hashedPacketlist(CPersist & data)
{
    for(int i = 0;i < data.c.get_rule_count();i++){
    	data.hashedPacketlist[i]->clear();
    	delete data.hashedPacketlist[i];
        //delete data.hashedPacketlist[i];
    }
    data.hashedPacketlist.clear();
    for(int i = 0;i < data.c.get_rule_count();i++){
        data.hashedPacketlist.push_back(new packetHashMap7());
    }
}

int main(int argc, char **argv) {

	const char * Date = __DATE__;
	const char * time = __TIME__;

	cout << "Evaluation of One-Way Flows V 0.1 (c) E. Glatz, N. Bigler, M. Fisler (build: ";
	cout << Date << " " << time << ")\n\n";

	// 1. Parse command line
	// *********************
	string list_filename;
	string rules_filename;
	string classes_filename;
	string pcap_filelist;

	bool test = false;
	bool verbose = false;
	bool verbose2 = false;
	bool use_outflows = false;
	bool analysis = false;

	string date("");

	int i;
	while ((i = getopt(argc, argv, "f:r:c:p:taOhd:vV")) != -1) {
		switch (i) {
			case 'f':
				list_filename = optarg;
				break;
			case 'r':
				rules_filename = optarg;
				break;
			case 'c':
				classes_filename = optarg;
				break;
			case 'p':
				pcap_filelist = optarg;
				break;
			case 'a':
				analysis = true;
				break;
			case 't':
				test = true;
				verbose = true;
				break;
			case 'O':
				use_outflows = true;
				cout << "\n### INFO: classifying outflows instead of inflows\n\n";
				break;
			case 'h':
				usage(argv[0], cout);
				exit(0);
				break;
			case 'd':
				date = optarg;
				if (date.size()!=8) {
					cerr << "\n\nERROR: invalid date string. Option -d expects a date of form YYYYMMSS.\n";
					usage(argv[0], cerr);
					exit(1);
				}
				break;
			case 'v':
				verbose = true;
				break;
			case 'V':
				verbose2 = true;
				break;
			default:
				cerr << "\n\nERROR: Unknown option: " << argv[optind] << endl;
				usage(argv[0], cerr);
				exit(1);
		}
	}

	vector<string> files;

	if (list_filename.size() > 0) {
		if (util::getSamples(list_filename, files)!=0) {
			cerr << "\ERROR: could not read files in " + list_filename << endl;
			exit(1);
		}
	} else {
		// Try to obtain filename from command line
		if ((argc - optind) == 1) {
			// We have one non-option argument: this must be the input file name
			string fname = argv[optind];
			files.push_back(fname);
		} else {
			cerr << "\nERROR: missing input file name.\n";
			usage(argv[0], cerr);
			exit(1);
		}
	}

	// Extract date and time of first interval flow data file
	size_t pos = files[0].find(".gz");
	if (pos == string::npos) {
		cerr << "ERROR: input file name " << files[0] << " does not end in .gz as it should.\n\n";
		exit(1);
	}
	string date_time;
	if (date.size()>0) {
		date_time = date + ".0000";
	} else {
		date_time = files[0].substr(pos-15, 13);	// Extract date/time as YYYYMMDD.hhmm
	}
	CPersist data(date_time, verbose, verbose2, test, rules_filename, classes_filename, use_outflows);

	// 2. Execute command
	// ******************

	if (files.size() > 1) { cout << "Processing file:\n"; }
	for (size_t i = 0; i< files.size(); i++) {
		if (files.size() > 1) { /*cout << files[i] << endl; */}
		process_interval(files[i], data, i, use_outflows);
	}

	vector<string> pcap_files;
	if (pcap_filelist.size() > 0) {
		if (util::getSamples(pcap_filelist, pcap_files)!=0) {
			cerr << "ERROR: could not read files in " + list_filename << endl;
			exit(1);
		}
	}else{
		cerr << "ERROR: no pcap file_list provided" << endl;
		usage(argv[0], cerr);
	}


	string pcap_filename;
	for (size_t i = 0; i< pcap_files.size(); i++) {
		if (pcap_files.size() > 1) { cout << pcap_files[i] << endl; }
		ifstream file(pcap_files[i].c_str(), ios_base::in | ios_base::binary);
		boost::iostreams::filtering_streambuf<boost::iostreams::input> in;
		pcap_filename = pcap_files[i].substr(0,pcap_files[i].find(".gz")).substr(pcap_files[i].find_last_of("/")+1);
		ofstream out(pcap_filename.c_str());
		in.push(boost::iostreams::gzip_decompressor());
		in.push(file);
		boost::iostreams::copy(in, out);
		cout << "Processing pcap file: " << pcap_filename << endl;
		process_pcap(pcap_filename, data, use_outflows);
		if (analysis){
			cout << "Clearing stats variables" << endl;
			clear_stats_variables(data);
			cout << "Generating stats" << endl;
			get_stats(data);
			get_icmp_false_positives(data, verbose);
			get_tcp_false_negatives(data, verbose);
			get_tcp_false_positives(data, verbose);
			cout << "Creating csv for stats"  << endl;
			print_stats(data, pcap_filename);
			get_affirmative_flow_count(data, verbose);
		}

		remove(pcap_filename.c_str());
		if (!analysis){
			write_pcap(data, use_outflows);
		}
		cout << "Clearing hashedPacketlist" << endl;
		clear_hashedPacketlist(data);

	}
	if (analysis){
		cout << "Creating csv for fp and fn." << endl;
		//write_stats_fp(data);
		//write_aff_stats(data);
		get_flow_count(data);
	}
}

uint8_t get_tcp_flags(tcphdr const &tcp_hdr) {
	return *(((uint8_t *)&(tcp_hdr.ack_seq))+5);
}

