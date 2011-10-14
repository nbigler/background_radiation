/*
 * main.cpp
 *
 *  Created on: Oct 1, 2011
 *      Author: Nicolas Bigler
 */
#include <cstring>
#include <string>
#include <iomanip>

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

// Util
#include "libs/HashMap.h"
#include "libs/utils.h"
#include "libs/flow.h"
#include "libs/flowlist.h"
#include "CPersist.h"



bool debug = false;

using namespace std;
using namespace pcappp;

// Hash key & map for storing flows
// ********************************
// key = 6-tuple (5-tuple + direction)
// data = references to flowlist records
//
typedef HashKeyIPv4_6T FlowHashKey6;
typedef hash_map<HashKeyIPv4_6T, struct flow, HashFunction<HashKeyIPv4_6T>, HashFunction<HashKeyIPv4_6T> > FlowHashMap6;
//typedef hash_map<HashKeyIPv4_6T, struct cflow *, HashFunction<HashKeyIPv4_6T>, HashFunction<HashKeyIPv4_6T> > CFlowHashMap6;

//void print_flow(std::pair<HashKeyIPv4_6T, flow> hash);
void print_cvs(std::pair<HashKeyIPv4_6T, flow> hash);
uint16_t endian_swap(uint16_t _x);
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
bool process_rules(CFlowlist * fl, uint32_t * fl_ref, CPersist & data, int inum)
{
	// 1. Initialize
	// *************
	int rule_count = data.c.get_rule_count();
	if (rule_count == 0) {
		return true;
	}
	int class_count = data.c.get_class_count();
	uint32_t total_flows = 0;
	uint32_t total_packets = 0;
	uint64_t total_bytes = 0;

	data.all_srcIP_hm.clear();
	data.all_dstIP_hm.clear();

	for (int i = 0; i < 65536; i++) data.all_dstPort_arr[i] = 0;

	for (int i = 0; i < rule_count; i++)  memset(data.dstPort_arr[i], 0, 65536);
	for (int i = 0; i < class_count; i++) memset(data.dstPort_arr2[i], 0, 65536);


	for (int i = 0; i < rule_count; i++) {
		data.flows[i] = 0;
		data.packets[i] = 0;
		data.bytes[i] = 0;
	}
	for (int k=0; k < rule_count; k++) {
		data.srcIP_hm[k].clear();
		data.dstIP_hm[k].clear();
	}

	for (int i = 0; i <= class_count; i++) {
		data.flows2[i] = 0;
		data.packets2[i] = 0;
		data.bytes2[i] = 0;
	}
	for (int k=0; k <= class_count; k++) {
		data.srcIP_hm2[k].clear();
		data.dstIP_hm2[k].clear();
	}


	if (data.verbose) {
		cout << "\n*** Applying rules/class definitions to sign sets\n";
	}

	data.c.clear();

	// 2. Classify Flows
	// *****************
	// Check every flow against all rules and rule-to-class associations

	// Maintain a counter per rule
	int * flow_per_rule_counter	= new int[rule_count];
	for (int j=0; j<rule_count; j++) {
		flow_per_rule_counter[j] = 0;
		data.hashedFlowlist.push_back(new CFlowHashMap6());
	}
	// Maintain a counter per rule
	int * flow_per_class_counter	= new int[class_count+1];
	for (int j = 0; j <= class_count; j++){
		flow_per_class_counter[j] = 0;

	}

	// Loop over all sign sets (i.e. all flows)
	int flow_count = fl->get_flow_count();
	for (int i=0; i<flow_count; i++) {
		if (fl_ref[i] != 0) { // Ignore empty sign sets
			struct cflow pflow = *fl->get_flow_at(i);
			total_flows++;
			total_packets += pflow.dPkts;
			total_bytes   += pflow.dOctets;
			//update_hm(data.all_srcIP_hm, pflow->remoteIP);
			//update_hm(data.all_dstIP_hm, pflow->localIP);
			if (pflow.prot == IPPROTO_TCP  || pflow.prot == IPPROTO_UDP) {
				data.all_dstPort_arr[pflow.localPort]++;  // We count flows per dst port
			}

			// Check signs against all rules and increment counters for matching ones
			bool found = false;
			for (int j=0; j<rule_count; j++) { // j is rule index
				if (data.c.rule_match(j, fl_ref[i])) {
					flow_per_rule_counter[j]++;
					// Update sign set of current rule
					data.rc.increment(j, fl_ref[i]);
					data.flows[j]++;
					data.packets[j] += pflow.dPkts;
					data.bytes[j]   += pflow.dOctets;
					FlowHashKey6 flowkey(&(pflow.remoteIP),&(pflow.localIP),&(pflow.remotePort),&(pflow.localPort),&(pflow.prot),&(pflow.dir));
					(*data.hashedFlowlist[j])[flowkey] = &pflow;
//					update_hm(data.srcIP_hm[j], pflow->remoteIP);
//					update_hm(data.dstIP_hm[j], pflow->localIP);
					if (pflow.prot == IPPROTO_TCP  || pflow.prot == IPPROTO_UDP) {
						data.dstPort_arr[j][pflow.localPort]++;  // We count flows per dst port
					}
					found = true;
				}
			}

			/*// Check signs against all classes and increment counters for matching ones
			bool found = false;
			for (int j=0; j<class_count; j++) { // j is class index
				if (data.c.class_match(j, fl_ref[i])) {
					flow_per_class_counter[j]++;
					// Update sign set of current class
					data.rc2.increment(j, fl_ref[i]);
					data.flows2[j]++;
					data.packets2[j] += pflow->dPkts;
					data.bytes2[j]   += pflow->dOctets;
					FlowHashKey6 flowkey(&(pflow->remoteIP),&(pflow->localIP),&(pflow->remotePort),&(pflow->localPort),&(pflow->prot),&(pflow->dir));
					//CFlowHashMap6 * test = data.hashedFlowlist[j];
					(*data.hashedFlowlist[j])[flowkey] = pflow;
					//(*data.hashedFlowlist[j])[flowkey] = pflow;
					/*update_hm(data.srcIP_hm2[j], pflow->remoteIP);
					update_hm(data.dstIP_hm2[j], pflow->localIP);
					if (pflow->prot == IPPROTO_TCP  || pflow->prot == IPPROTO_UDP) {
						data.dstPort_arr2[j][pflow->localPort]++; // We count flows per dst port
					}
					found = true;
				}
			}*/

    bool other_class = !found && class_count > 0;
    // Handle situation that "no rule/class applies"
    if(other_class) { // Add class "other" having no definition
				flow_per_class_counter[class_count]++;
				// Update sign set of remainder class "other"
				data.rc2.increment(class_count, fl_ref[i]);
				data.flows2[class_count]++;
				data.packets2[class_count] += pflow.dPkts;
				data.bytes2[class_count]   += pflow.dOctets;
				FlowHashKey6 flowkey(&(pflow.remoteIP),&(pflow.localIP),&(pflow.remotePort),&(pflow.localPort),&(pflow.prot),&(pflow.dir));
				(*data.hashedFlowlist[class_count])[flowkey] = &pflow;
				/*update_hm(data.srcIP_hm2[class_count], pflow->remoteIP);
				update_hm(data.dstIP_hm2[class_count], pflow->localIP);
				if (pflow->prot == IPPROTO_TCP  || pflow->prot == IPPROTO_UDP) {
					data.dstPort_arr2[class_count][pflow->localPort]++;
				}*/
			}
		}
		if (data.verbose) { if ((i % 100000) == 0) { cout << "."; cout.flush(); } }
	}
	cout << endl;


	return true;
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
    cout << "\nRead " << in.gcount() / 2 << " values from sig file " << sign_filename << endl;
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
	string pcap_filename;

	bool test = false;
	bool verbose = false;
	bool verbose2 = false;
	bool use_outflows = false;

	string date("");

	int i;
	while ((i = getopt(argc, argv, "f:r:c:p:tOhd:vV")) != -1) {
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
				pcap_filename = optarg;
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
		int result = util::getSamples(list_filename, files);
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
	for (int i = 0; i< files.size(); i++) {
		if (files.size() > 1) { cout << files[i] << endl; }
		process_interval(files[i], data, i, use_outflows);
	}

	FlowHashMap6 * flowHM6 = new FlowHashMap6();
	FlowHashMap6::iterator iter;



	struct flow flow;
	memset((void *)&flow, 0,sizeof(flow));

	if (pcap_filename == "") {
		cerr << "ERROR: no pcap file name specified on command line.\n";
		usage(argv[0], cerr);
		exit(1);
	}
	/*if (argc != 2){
		cerr << "ERROR: no pcap file name specified on command line.\n";
		exit(1);
	}*/
	// Open file for packet reading
	int pcount = 0;	// Packet counter
	try {
		PcapOffline pco(pcap_filename);
		//PcapOffline pco(argv[1]);
		// Get some general infos from file
		string filename = pco.get_filename();
		//cout << "File name is: " << filename << endl;

		int major = pco.get_major_version();
		int minor = pco.get_minor_version();
		cout << "File format used is: " << major << "." << minor << endl;

		if (pco.is_swapped()) {
			//cout << "Capture data byte order differs from byte order used on this system.\n";
		} else {
			//cout << "Capture data byte order complies with byte order used on this system.\n";
		}

		DataLink dl = pco.get_datalink();
		//cout << "Data link code: " << dl.get_description() << endl;

		if (dl.get_type() == DataLink::EN10MB) {
			//cout << "INFO: data link type is standard Ethernet (10 MB up).\n";
		} else {
			//cout << "INFO: data link type is NOT Ethernet. Type code is: " << dl.get_type() << ".\n";
			//cout << "\nAll done.\n\n";
			return 0;
		}

		//unsigned int slen = pco.get_snaplen();
		//cout << "Snap length: " << slen << endl << endl;

		//cout << "Packet header details (for IPv4 packets):\n";

		// Process saved packets
		// *********************
		// Loop through pcap file by reading packet-by-packet.
		Packet p;
		while (pco.ok()) {
			flow = {};
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

			// cout << pcount << ": ";
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
				inet_pton(AF_INET, "10.0.0.2", &netmask);
				// Show transport layer protocol
				if ((ip_hdr->saddr&netmask) == netmask){
					flow.init(ip_hdr->saddr, ip_hdr->daddr, ip_hdr->protocol, outflow);
				}else{
					flow.init(ip_hdr->daddr, ip_hdr->saddr, ip_hdr->protocol, inflow);
				}
				flow.tos_flags = ip_hdr->tos;
				ipPayload payload;

				switch (ip_hdr->protocol) {
				case IPPROTO_TCP:
					tcp_hdr = (struct tcphdr *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					flow.localPort = endian_swap(tcp_hdr->source);
					flow.remotePort = endian_swap(tcp_hdr->dest);
					payload.tcpHeader = tcp_hdr;
					payload.payload = (char * )(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr));
					break;
				case IPPROTO_UDP:
					udp_hdr = (struct udphdr *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					flow.localPort = endian_swap(udp_hdr->source);
					flow.remotePort = endian_swap(udp_hdr->dest);
					payload.udpHeader = udp_hdr;
					payload.payload = (char * )(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr));
					break;
				case IPPROTO_ICMP:
					icmp_hdr = (struct icmphdr *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					payload.icmpHeader = icmp_hdr;
					payload.payload = (char * )(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr));
					break;
				default:
					payload.payload = (char *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					break;
				}
				payload.timestamp = p.get_seconds()*1000000 + p.get_miliseconds();
				payload.packetsize = p.get_capture_length();
				flow.payload.push_back(payload);

				// Check if current flow is already contained in hash map
//				FlowHashKey6 mykey(&(flow.localIP), &(flow.remoteIP), &(flow.localPort),
//					&(flow.remotePort), &(flow.protocol), &(flow.flowtype));
//
//
//				iter = flowHM6->find(mykey);

//				if (iter == flowHM6->end()) { //no matching flow found
//					if (iter_inverse == flowHM6->end()){ //no matching inverse flow found
//						if (iter_biflow == flowHM6->end()) { //no matching biflow found
//							flow.startMs = p.get_seconds()*1000000 + p.get_miliseconds(); //get_miliseconds() returns microseconds not milliseconds
//							flow.dOctets = p.get_capture_length();
//							flow.dPkts = 1;
//							(*flowHM6)[mykey] = flow;
//						}else{
//							(*flowHM6)[mykey_biflow].durationMs = p.get_seconds()*1000000 + p.get_miliseconds() - (*flowHM6)[mykey_biflow].startMs;
//							(*flowHM6)[mykey_biflow].dOctets = p.get_capture_length() + (*flowHM6)[mykey_biflow].dOctets;
//							(*flowHM6)[mykey_biflow].dPkts = (*flowHM6)[mykey_biflow].dPkts + 1;
//							(*flowHM6)[mykey_biflow].payload.push_back(flow.payload.at(0));
//						}
//					}
//				}
			} /*else {

				// Handle all non-IPv4 traffic
				// ***************************

				switch (ntohs(ether_hdr->h_proto)) {
				case  ETH_P_ARP:
					cout << "ARP packet\n";
					break;
				case ETH_P_IPV6:
					cout << "IPv6 packet\n";
					break;
				default:
					cout << "non-IPv4 packet. Protocol code is: 0x";
					char prev = cout.fill('0');
					streamsize oldwidth = cout.width(4);
					cout << hex << ntohs(ether_hdr->h_proto) << dec << endl;
					cout.fill(prev);
					cout.width(oldwidth);
					break;
				}
			}*/
		}

	} catch (PcapError & pcerror) {

		cerr << "ERROR: " << pcerror.what() << endl;

	} catch (...) {
		cout << "ERROR: unknown exception occurred.\n";
	}
	//for_each(flowHM6->begin(),flowHM6->end(),print_flow);
	cout << "Local IP; Local Port; Remote IP; Remote Port; Protocol; ToS-Flags; TCP-Flags; Flow-Size; Number of Packets; Direction; Start Time; Duration" << endl;

	for_each(flowHM6->begin(),flowHM6->end(),print_cvs);
}

uint16_t endian_swap(uint16_t _x){
	uint16_t x = _x;
	x = (x>>8) | (x<<8);
	return x;
}

void print_cvs(std::pair<HashKeyIPv4_6T, flow> hash){
	flow flow = hash.second;
	char localIP[INET_ADDRSTRLEN];
	char remoteIP[INET_ADDRSTRLEN];
	util::ipV4AddressToString(flow.localIP,localIP,INET_ADDRSTRLEN);
	util::ipV4AddressToString(flow.remoteIP,remoteIP,INET_ADDRSTRLEN);
	for (uint i = 0; i < flow.dPkts; i++){
		uint8_t tcp_flags = *(((uint8_t *)&(flow.payload[i].tcpHeader->ack_seq))+5);
//		int flags = tcp_flags;
		cout <<  localIP << "; " << flow.localPort << "; " << remoteIP << "; " << flow.remotePort << "; ";
		cout << util::ipV4ProtocolToString(flow.protocol) << "; 0x" << hex << static_cast<unsigned int>(tcp_flags) << dec << "; " << flow.payload[i].packetsize << "; " << i+1 << "; ";
		switch (flow.flowtype) {
			case outflow:
				cout << "outflow";
				break;
			case inflow:
				cout << "inflow";
				break;
			case biflow:
				cout << "biflow";
				break;
			default:
				cout << "other";
				break;
		}

	cout.precision(10);
	//cout << "; " << fixed << 25569+((flow.startMs/(double) 1000)/(double) 86400);  // Pre-Formated for Excel/LibreOffice
	cout << "; " << fixed << (flow.payload[i].timestamp);  // Unix-Timestamp
	cout << "; " << (flow.payload[i].timestamp - flow.startMs) << endl;
	//cout << "sizeof(tcp_flags): " << sizeof(tcp_flags) << endl;
	}
}
void print_flow(std::pair<HashKeyIPv4_6T, flow> hash){
	flow flow = hash.second;
	char localIP[INET_ADDRSTRLEN];
	char remoteIP[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(flow.localIP), localIP, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(flow.remoteIP), remoteIP, INET_ADDRSTRLEN);
	cout << "Local IP: " << localIP << "\tLocal Port: " << flow.localPort << endl;
	cout << "Remote IP: " << remoteIP << "\tRemote Port: " << flow.remotePort << endl;
	cout << "Protocol: ";
	switch (flow.protocol) {
		case IPPROTO_TCP:
			cout << "TCP";
			break;
		case IPPROTO_UDP:
			cout << "UDP";
			break;
		default:
			cout << "Other";
			break;
	}
	cout << endl;
	if (flow.protocol==IPPROTO_TCP){cout << "TCP-Flags: 0x" << hex << (int) flow.tos_flags << endl;}
	cout << "Flow-Size (Byte): " << dec << flow.dOctets << endl;
	cout << "Number of Packets: " << flow.dPkts << endl;
	cout << "Direction: ";
	switch (flow.flowtype) {
		case outflow:
			cout << "outflow";
			break;
		case inflow:
			cout << "inflow";
			break;
		case biflow:
			cout << "biflow";
			break;
		default:
			cout << "unknown";
			break;
	}
	cout << endl;
	time_t rawtime = flow.startMs;
	cout << "Start Time: " << ctime(&rawtime) << "ms \tDuration: " << flow.durationMs << "ms" << endl;
	cout << "-----------------------" << endl;
}

bool valid_flag_sequence_check(flow flow) {
	for (uint i = 0; i < flow.dPkts; i++){
//		flow.payload[i].tcpHeader->
		//TODO flag decoding, flag categorization
	}
	return true;
}

uint8_t get_tcp_flags(tcphdr const &tcp_hdr) {
	return *(((uint8_t *)&(tcp_hdr.ack_seq))+5);
}

