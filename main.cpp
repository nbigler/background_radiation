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
#include "Flow.h"



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
		data.flows_by_rule.push_back(new CFlowHashMap6());
		//data.hashedPacketlist.push_back(new packetHashMap7());
		//data.rules_packetlist.push_back(new vector<packet>());
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

			/*static char local[16];
			static char remote[16];
			util::ipV4AddressToString(pflow->localIP, local, sizeof local);
			util::ipV4AddressToString(pflow->remoteIP, remote,sizeof remote);
			cout << "Flow: " << local << ":" << pflow->localPort << ";\t" << remote << ":" << pflow->remotePort << ";" << static_cast<int>(pflow->prot) << endl;
*/
			for (int j=0; j<rule_count; j++) { // j is rule index
				if (data.c.rule_match(j, fl_ref[i])) {
					flow_per_rule_counter[j]++;
					// Update sign set of current rule
					data.rc.increment(j, fl_ref[i]);
					/*data.flows[j]++;
					data.packets[j] += pflow->dPkts;
					data.bytes[j]   += pflow->dOctets;*/
					FlowHashKey6 flowkey(&(pflow->localIP),&(pflow->remoteIP),&(pflow->localPort),&(pflow->remotePort),&(pflow->prot),&(pflow->flowtype));

//					CFlowHashMap6::iterator iter = (*data.flows_by_rule[j]).find(flowkey);

					(*data.flows_by_rule[j]).insert(CFlowHashMap6::value_type (flowkey, Flow(*pflow)));
					found = true;
				}
			}
			if (!found) {
				flow_per_rule_counter[rule_count]++;
				// Update sign set of current rule
				data.rc.increment(rule_count, fl_ref[i]);
				/*data.flows[rule_count]++;
				data.packets[rule_count] += pflow->dPkts;
				data.bytes[rule_count]   += pflow->dOctets;*/

				FlowHashKey6 flowkey(&(pflow->localIP),&(pflow->remoteIP),&(pflow->localPort),&(pflow->remotePort),&(pflow->prot),&(pflow->flowtype));
//				CFlowHashMap6::iterator iter = (*data.flows_by_rule[rule_count]).find(flowkey);
//				(*data.flows_by_rule[rule_count]).insert(CFlowHashMap6::value_type (flowkey, Flow(*pflow)));
			}
		}else {
			usflows++;
		}
		pflow = fl->get_next_flow();
		i++;
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
    // Read per-flow sign sets to memory, i.e., array "flpush_back(p);_ref".
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
	int flow_count = fl->get_flow_count();
	if (data.verbose) cout << endl << flow_count << " flows read from file " << filename << endl;


    uint32_t *fl_ref = read_per_flow_sign_sets(filename, use_outflows, flow_count);

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


bool file_exists(string filename)
{
    if (FILE * file = fopen(filename.c_str(), "r"))
    {
        fclose(file);
        return true;
    }
    return false;
}

void write_pcap(CPersist & data){

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
	    pcapFileHeader(){
	    	magic_number = 0xa1b2c3d4;
			version_major = 2;
			version_minor = 4;
			thiszone = 0;
			sigfigs = 0;
			snaplen = 65535;
			network = 1;
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

	//pcapFileHeader fileHeader(0xa1b2c3d4, 2, 4, 0, 0, 65535, 1);
	pcapFileHeader fileHeader;

	pcapPacketHeader packetHeader;
	ofstream fileout;
	string rulename;
	string filename;

	for (int i = 0; i<= data.c.get_rule_count(); i++){
		if (i == data.c.get_rule_count()){
			rulename = "Other";
		} else {
			data.c.get_rule_name(i, rulename);
		}
		filename = "rule_" + rulename + ".pcap";

		if (!file_exists(filename)){
			fileout.open(filename.c_str(), ios::trunc | ios::binary);
			fileout.write(reinterpret_cast<const char*>(&fileHeader),
							  sizeof fileHeader);
		}else{
			fileout.open(filename.c_str(), ios::app | ios::binary);
		}
		vector<packet>::iterator iter;
		//iter != data.rules_packetlist[i]->end()
		CFlowHashMap6::iterator it;
		for (it = data.flows_by_rule[i]->begin(); it != data.flows_by_rule[i]->end() ; it++){
			for (vector<packet>::const_iterator iter = (*it).second.get_packets().begin(); iter != (*it).second.get_packets().end(); iter++){
				packetHeader.init((*iter).ipPayload.timestamp, (*iter).ipPayload.packetsize, (*iter).ipPayload.actualsize);
				fileout.write(reinterpret_cast<const char*>(&packetHeader), sizeof packetHeader);
				fileout.write(reinterpret_cast<const char*>(&(*iter).ethHeader), sizeof(struct ethhdr));
				fileout.write(reinterpret_cast<const char*>(&(*iter).ipHeader), sizeof(struct iphdr));
				switch ((*iter).protocol) {
					case IPPROTO_TCP:
						fileout.write(reinterpret_cast<const char*>(&(*iter).ipPayload.tcpHeader), sizeof(struct tcphdr));
						//fileout.write(reinterpret_cast<const char*>(&it->ipPayload.payload), it->ipPayload.packetsize - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr)));
						break;
					case IPPROTO_UDP:
						fileout.write(reinterpret_cast<const char*>(&(*iter).ipPayload.udpHeader), sizeof(struct udphdr));
						//fileout.write(reinterpret_cast<const char*>(&it->ipPayload.payload), it->ipPayload.packetsize - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)));
						break;
					case IPPROTO_ICMP:
						fileout.write(reinterpret_cast<const char*>(&(*iter).ipPayload.icmpHeader), sizeof(struct icmphdr));
						//fileout.write(reinterpret_cast<const char*>(&p.ipPayload.payload), p.ipPayload.packetsize - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr)));
						break;
					default:
						//fileout.write(reinterpret_cast<const char*>(&p.ipPayload.payload), p.ipPayload.packetsize - (sizeof(struct ethhdr)+sizeof(struct iphdr)));
						break;
				}
			}
		}
		fileout.close();
	}
}

void find_match(packet &p, CPersist & data){

	uint8_t in = inflow;
	uint8_t q_in = q_infl;

	FlowHashKey6 mykey(&(p.remoteIP), &(p.localIP), &(p.remotePort),
					&(p.localPort), &(p.protocol), &(in));
	FlowHashKey6 mykey_q(&(p.remoteIP), &(p.localIP), &(p.remotePort),
					&(p.localPort), &(p.protocol), &(q_in));

	for (int i = 0; i <= data.c.get_rule_count(); i++){
		CFlowHashMap6::iterator iter = data.flows_by_rule[i]->find(mykey);
		CFlowHashMap6::iterator iter_q = data.flows_by_rule[i]->find(mykey_q);

		if (iter != data.flows_by_rule[i]->end()){

			cflow fl = (*iter).second.get_flow();
			if ((fl.startMs <= p.ipPayload.timestamp/1000) && (p.ipPayload.timestamp/1000 <= (fl.startMs + fl.durationMs))){
//				(*data.rules_packetlist[i]).push_back(p);
				(*iter).second.add(p);
			}
		} else if(iter_q != data.flows_by_rule[i]->end()){

			cflow fl = (*iter_q).second.get_flow();
			if ((fl.startMs <= p.ipPayload.timestamp/1000) && (p.ipPayload.timestamp/1000 <= (fl.startMs + fl.durationMs))){
//				(*data.rules_packetlist[i]).push_back(p);
				(*iter_q).second.add(p);
			}
		}
	}
}

void process_pcap(string pcap_filename, CPersist & data, time_t cflow_start)
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

				//uint32_t netmask;
				//inet_pton(AF_INET, "152.103.0.0", &netmask);
				// Show transport layer protocol
				packet.init(ip_hdr->saddr, ip_hdr->daddr, ip_hdr->protocol);
				//packet.tos_flags = ip_hdr->tos;
				packet.ethHeader = *ether_hdr;
				packet.ipHeader = *ip_hdr;
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

				/*static char local[16];
				static char remote[16];
				util::ipV4AddressToString(packet.localIP, local, sizeof local);
				util::ipV4AddressToString(packet.remoteIP, remote,sizeof remote);
				cout << "Packet: " << local << ":" << packet.localPort << ";\t" << remote << ":" << packet.remotePort << ";" << static_cast<int>(packet.protocol)<< endl;*/

				if ((cflow_start < (packet.ipPayload.timestamp / 100000)) && ((cflow_start + 600) > (packet.ipPayload.timestamp / 1000000))){
					find_match(packet, data);
				}
			}
		}

	} catch (PcapError & pcerror) {

		cerr << "ERROR: " << pcerror.what() << endl;

	} catch (...) {
		cout << "ERROR: unknown exception occurred.\n";
	}
}

void get_flow_count(CPersist &data){
	ofstream out;
	string statfile_flowcount = "flowcount.csv";
	util::open_outfile(out, statfile_flowcount);
	out << "Rule;Flow-Count;Packet-Count" << endl;
	long total_rflows = 0;
	for (int i=0; i <= data.c.get_rule_count(); i++){
		int flowcount = 0;
		int packetcount = 0;
		cout << "Rule: " << i << endl;
//		int interval = 2;
		for (CFlowHashMap6::iterator it = data.flows_by_rule[i]->begin(); it != data.flows_by_rule[i]->end(); it++){
			++flowcount;
			cflow fl = (*it).second.get_flow();
			packetcount += fl.dPkts;
		}
		string rulename;
		data.c.get_rule_name(i, rulename);
		out << rulename << ";" << flowcount << ";" << packetcount << endl;
		total_rflows += flowcount;
	}

	out.close();
	cout << "Total Flows in all rules: " << total_rflows << endl;
	cout << "--------------" << endl;
	cout << "Total Flows with same key: " << doubleflows << endl;
	cout << "Total Flows with signs: " << sflows << endl;
	cout << "Total Flows without signs: " << usflows << endl;
	cout << "Total Flows: " << totalflows << endl;
}

void clear_lists(CPersist & data){
	for (int i=0; i <= data.c.get_rule_count(); i++) {
		data.flows_by_rule[i]->clear();
		delete data.flows_by_rule[i];
//		data.rules_packetlist[i]->clear();
//		delete data.rules_packetlist[i];
	}
	data.flows_by_rule.clear();
//	data.rules_packetlist.clear();
}

bool flowlist_not_complete(CPersist & data){

	vector<CFlowHashMap6*>::iterator it;
	CFlowHashMap6::iterator cfHmiter;
	for (it=data.flows_by_rule.begin(); it!=data.flows_by_rule.end(); it++){
		for (cfHmiter = (*it)->begin(); cfHmiter != (*it)->end(); cfHmiter++){
			if (cfHmiter->second.get_flow().dPkts != cfHmiter->second.get_packets().size()){
				return false;
			}
		}
	}

	return true;
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

	if (files.size() > 1) { cout << "Processing file:\n"; }
	for (size_t i = 0; i< files.size(); i++) {
		if (files.size() > 1) { cout << files[i] << endl;}
		process_interval(files[i], data, i, use_outflows);
		if (!analysis){
			pos = files[i].find(".gz");
			if (pos == string::npos) {
				cerr << "ERROR: input file name " << files[0] << " does not end in .gz as it should.\n\n";
				exit(1);
			}
			string date_time;
			date_time = files[i].substr(pos-15, 13);

			struct tm tm = {};
			time_t cts = 0;
			if (strptime(date_time.c_str(),"%Y%m%d.%H%M",&tm) == NULL){
				cerr << "Something went wrong" << endl;
			}
			tm.tm_hour++;
			cts = mktime(&tm);
			if(verbose) {
				cout << "date_time: " << date_time << endl;
				cout << "cts: " << cts << endl;
			}

			string pcap_filename;

			if(verbose) {
				cout << "Pcap Filename: " << pcap_filename << endl;
			}

			for (size_t j = 0; j< pcap_files.size(); j++) {
				if (pcap_files.size() > 1) { cout << pcap_files[j] << endl; }
				pos = pcap_files[j].find(".pcap.gz");
				string pcap_ts;
				pcap_ts = pcap_files[j].substr(pos-10,10);
				time_t pts = atoi(pcap_ts.c_str());
				cout << "pts: " << pts << endl;
				if (((cts < pts) && (cts+600 > pts)) || ((cts > pts) && (cts < pts + 3600)) || flowlist_not_complete(data)){
					cout << "if entered" << endl;
					pcap_filename = pcap_files[j].substr(0,pcap_files[j].find(".gz")).substr(pcap_files[j].find_last_of("/")+1);
					if (!file_exists(pcap_filename)){
						if (j>0) remove(pcap_files[j-1].c_str());
						ifstream file(pcap_files[j].c_str(), ios_base::in | ios_base::binary);
						boost::iostreams::filtering_streambuf<boost::iostreams::input> in;
						ofstream out(pcap_filename.c_str());
						in.push(boost::iostreams::gzip_decompressor());
						in.push(file);
						boost::iostreams::copy(in, out);
					}
					cout << "Processing pcap file: " << pcap_filename << endl;
					process_pcap(pcap_filename, data, cts);
				}
			}
			write_pcap(data);
			clear_lists(data);
		}
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
