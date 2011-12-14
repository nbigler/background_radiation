/**
 *	\file pcap_validator.cpp
 *	\brief Classify pcap files based on the signes of the appropriate flow data.
 *	As input flow data files stored in "struct cflow" format (*.gz) and associated
 *	sign data files (*.sig.gz) and pcap data files stored in tcpdump format (*.pcap.gz)
 *	are read. The pcap packets are matched with the appropriate flow and written to a new
 *	pcap file that corresponds to the associated rule.
 *
 *	Compile with:
 *	g++ category.cpp CPersist.cpp pcap_validator.cpp libs/flowlist.cpp libs/HashMap.cpp libs/lookup3.cpp libs/utils.cpp -lpcap++ -lboost_iostreams -o pcap_validator -Wno-deprecated -O3
 *
 *
 * 	Copyright (c) 2011, Eduard Glatz, Nicolas Bigler, Michael Fisler
 *
 * 	Author: Eduard Glatz  (eglatz@tik.ee.ethz.ch)
 * 			Nicolas Bigler (nbigler@hsr.ch)
 * 			Michael Fisler (mfisler@hsr.ch)
 *
 *	Distributed under the Gnu Public License version 2 or the modified
 *	BSD license.
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

// Util
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

/**
 *	Classifies flows by applying rules and rule-to-class assocciations to actual
 *	sign sets of given flows. For each rule/class a flow matches the assigned
 *	counter is incremented. After all flows have been processed overall count
 *	values are written as new lines to statistics CSV files.
 *
 *
 *	\param	fl			Flowlist
 *	\param	fl_ref		List of sign sets aligned with fl
 *	\param	data		Persistent statistics variables needed for overall statistics.
 *	\param	inum		Number of currenr interval
 */
void process_rules(CFlowlist * fl, uint32_t * fl_ref, CPersist & data,
		int inum, string rulename) {
	// 1. Initialize
	// *************
	int rule_no = data.c.get_rule_number(rulename);

	uint32_t total_flows = 0;
	uint32_t total_packets = 0;
	uint64_t total_bytes = 0;

	if (data.verbose) {
		cout << "\n*** Applying rules/class definitions to sign sets\n";
	}

	data.c.clear();
	// 2. Classify Flows
	// *****************
	// Check every flow against all rules and rule-to-class associations

	// Loop over all sign sets (i.e. all flows)
	int i = 0;
	struct cflow * pflow = fl->get_first_flow();
	data.last_flow = 0;
	uint32_t duration = 0;
	while (pflow != NULL) {
		totalflows++;
		if (fl_ref[i] != 0) { // Ignore empty sign sets
			sflows++;
			total_flows++;
			total_packets += pflow->dPkts;
			total_bytes += pflow->dOctets;
			util::swap_endians(*pflow);

			if (pflow->prot == IPPROTO_ICMP) {
				pflow->localPort = 0;
				pflow->remotePort = 0;
			}

			if (data.last_flow < (pflow->startMs + pflow->durationMs)) {
				data.last_flow = (pflow->startMs + pflow->durationMs);
			}
			if (duration < pflow->durationMs) {
				duration = pflow->durationMs;
			}
			// Check signs against all rules and increment counters for matching ones


			if (data.c.rule_match(rule_no, fl_ref[i])) {
				// Update sign set of current rule
				//data.rc.increment(rule_no, fl_ref[i]);

				FlowHashKey6 flowkey(&(pflow->localIP), &(pflow->remoteIP),
						&(pflow->localPort), &(pflow->remotePort),
						&(pflow->prot), &(pflow->flowtype));

				(*data.flowHashMap).insert(
						CFlowHashMultiMap6::value_type(flowkey,
								Flow(*pflow)));
			}
		}

		pflow = fl->get_next_flow();
		i++;
	}
	if (data.verbose)
		cout << "Longest Flow is " << duration << " ms and ends at "
				<< data.last_flow << endl;
}

/**
 *	Checks the status of the sign file
 *	If the file is not accessible the program exits with status 1.
 *
 *	\param	sign_filename	Path of the sign (*.sig.gz) file
 */
void check_file_status(string & sign_filename) {
	struct stat fileStatus;
	int iretStat = stat(sign_filename.c_str(), &fileStatus);
	if (iretStat == -1) {
		cerr << "\nERROR: " << sign_filename
				<< " does not exist or is not accessible.\n";
		perror("stat()");
		cerr << "Check file name.\n\n";
		char buf[256];
		getcwd(buf, 256);
		cout << "Current working directory is: " << buf << endl;
		exit(1);
	}
}

/**
 *	Reads a total of 'flow_count' flows from 'filename'.gz
 *	and save them to the list 'fl_ref.
 *
 *	\param	filename		Filename of the struct cflow file (*.gz)
 *	\param	flow_count		number of flows to read
 *	\return fl_ref			uint32_t Pointer to the flowlist
 */
uint32_t *read_per_flow_sign_sets(string & filename, int flow_count) {
	// 2. Get per-flow sign sets
	// *************************
	string basename = filename.substr(0, filename.find(".gz"));
	string sign_filename;
	sign_filename = basename + ".sig.gz";
	check_file_status(sign_filename);
	// Read per-flow sign sets to memory, i.e., array "flpush_back(p);_ref".
	uint32_t *fl_ref = new uint32_t[flow_count];
	// Open up a stream chain
	boost::iostreams::filtering_istream in;
	// Add stream compressor
	in.push(boost::iostreams::gzip_decompressor());
	// Open input file and link it to stream chain
	boost::iostreams::file_source infs(sign_filename);
	if (!infs.is_open()) {
		cerr << "ERROR: could not open file source \"" << sign_filename
				<< "\".\n";
		exit(1);
	}
	in.push(infs);
	// Now get all sign sets
	in.read((char*) (((fl_ref))), flow_count * sizeof(uint32_t));
	//cout << "\nRead " << in.gcount() / 2 << " values from sig file " << sign_filename << endl;
	// Close current input file (and stream compressor)
	in.pop();
	return fl_ref;
}

/**
 *	Process flow and sign data from one time interval.
 *
 *	\param filename	  Name of flow data input file (name of sign file is derived from this name)
 *	\param data         Cross-interval data (e.g. counters and output streams)
 *	\param inum         Interval number (first interval must have inum=0)
 *
 *	\return TRUE if processing successful, FALSE otherwise
 */
bool process_interval(string & filename, CPersist & data, int inum, string rulename) {
	CFlowlist * fl = new CFlowlist(filename);
	fl->read_flows();
	int flow_count = fl->get_flow_count();
	if (data.verbose)
		cout << endl << flow_count << " flows read from file " << filename
				<< endl;

	uint32_t *fl_ref = read_per_flow_sign_sets(filename, flow_count);

	process_rules(fl, fl_ref, data, inum, rulename);

	delete[] fl_ref;
	delete fl;
	return true;
}

/**
 *	Print the usage information on the screen.
 *
 *	\param progname		Name of the program
 *	\param outfs        Stream to write the usage informations to
 */
void usage(char * progname, ostream & outfs) {
	outfs
			<< "\nEvaluates signs assigned to one-way flows. One or more file names \n";
	outfs
			<< "of flow data files are expected. To specify more than one input file name\n";
	outfs << "use option -f and a file containing a list of file names.\n";
	outfs
			<< "Unless option -d is used an input file name *YYYYMMDD.hhmm.gz is expected.\n";

	outfs << "Usage: " << progname
			<< " [options] [pcap_file] [input_filename]\n\n";

	outfs << "Options:\n";
	outfs
			<< "-f <filename>  File containing list of input file names (default: [use input_filename]).\n";
	outfs
			<< "-r <filename>  Create sign statistics by rules stored in <filename> (default: none)\n";
	outfs
			<< "-c <filename>  Create sign statistics by classes stored in <filename> (default: none)\n";
	outfs
			<< "-p <filename>  pcap file of the flow data corresponding to the flows in *.gz files\n";
	outfs << "-t             Run sanity checks only.\n";
	outfs << "-O             Classify ouflows instead of inflows.\n";
	outfs
			<< "-d <date>      Date of form YYYYMMDD to be used in file naming (default: extracted from file name).\n";
	outfs << "-h             Show help info.\n";
	outfs << "-v             Show additional informative messages.\n";

	outfs << endl;
}

/**
 *	Checks if a file with 'filename' exists
 *	Returns true if file exists, otherwise returns false.
 *
 *	\param filename	  Name of file to check
 *
 *	\return TRUE if file exists, FALSE otherwise
 */
bool file_exists(string filename) {
	if (FILE * file = fopen(filename.c_str(), "r")) {
		fclose(file);
		return true;
	}
	return false;
}

/**
 *	Writes all packets in the rules_packetlist vector to
 *	the associated rule pcap file.
 *
 *	\param data	  CPersist object containing all data
 */
void write_pcap(CPersist & data) {
	//
	//	struct pcapFileHeader {
	//	    uint32_t magic_number;   /* magic number */
	//	    uint16_t version_major;  /* major version number */
	//	    uint16_t version_minor;  /* minor version number */
	//	    int16_t  thiszone;       /* GMT to local correction */
	//	    uint32_t sigfigs;        /* accuracy of timestamps */
	//	    uint32_t snaplen;        /* max length of captured packets, in octets */
	//	    uint32_t network;        /* data link type */
	//
	//	    pcapFileHeader (uint32_t magic, uint16_t major, uint16_t minor,
	//	    		int16_t zone, uint32_t ts_acc, uint32_t max_packlen, uint32_t dl_type){
	//	    	magic_number = magic;
	//	    	version_major = major;
	//	    	version_minor = minor;
	//	    	thiszone = zone;
	//	    	sigfigs = ts_acc;
	//	    	snaplen = max_packlen;
	//	    	network = dl_type;
	//	    }
	//	    pcapFileHeader(){
	//	    	magic_number = 0xa1b2c3d4;
	//			version_major = 2;
	//			version_minor = 4;
	//			thiszone = 0;
	//			sigfigs = 0;
	//			snaplen = 65535;
	//			network = 1;
	//	    }
	//	};
	//
	//	struct pcapPacketHeader {
	//	    uint32_t ts_sec;         /* timestamp seconds */
	//	    uint32_t ts_usec;        /* timestamp microseconds */
	//	    uint32_t incl_len;       /* number of octets of packet saved in file */
	//	    uint32_t orig_len;       /* actual length of packet */
	//
	//	    void init (uint64_t timestamp, uint32_t packetsize, uint32_t actualsize) {
	//	    	ts_sec = timestamp/1000000;
	//	    	ts_usec = timestamp%1000000;
	//	    	incl_len = packetsize;
	//	    	orig_len = actualsize;
	//	    }
	//	};
	//
	//	//pcapFileHeader fileHeader(0xa1b2c3d4, 2, 4, 0, 0, 65535, 1);
	//	pcapFileHeader fileHeader;
	//
	//	pcapPacketHeader packetHeader;
	//	ofstream fileout;
	//	string rulename;
	//	string filename;
	//
	//	for (int i = 0; i<= data.c.get_rule_count(); i++){
	//		if (i == data.c.get_rule_count()){
	//			rulename = "Other";
	//		} else {
	//			data.c.get_rule_name(i, rulename);
	//		}
	//		filename = "rule_" + rulename + ".pcap";
	//
	//		if (!file_exists(filename)){
	//			fileout.open(filename.c_str(), ios::trunc | ios::binary);
	//			fileout.write(reinterpret_cast<const char*>(&fileHeader),
	//							  sizeof fileHeader);
	//		}else{
	//			fileout.open(filename.c_str(), ios::app | ios::binary);
	//		}
	//		vector<packet>::iterator iter;
	//		for (iter = data.rules_packetlist[i]->begin(); iter != data.rules_packetlist[i]->end(); iter++){
	//		//for (CFlowHashMultiMap6::iterator it = data.flows_by_rule[i]->begin(); it != data.flows_by_rule[i]->end() ; it++){
	//			//if((*it).second.flow_complete()) {
	//				//for (vector<packet>::const_iterator iter = (*it).second.get_packets().begin(); iter != (*it).second.get_packets().end(); iter++){
	//			packetHeader.init((*iter).timestamp, (*iter).packetsize, (*iter).actualsize);
	//			fileout.write(reinterpret_cast<const char*>(&packetHeader), sizeof packetHeader);
	//			fileout.write(reinterpret_cast<const char*>(&(*iter).ethHeader), sizeof(struct ethhdr));
	//			fileout.write(reinterpret_cast<const char*>(&(*iter).ipHeader), sizeof(struct iphdr));
	//			switch ((*iter).protocol) {
	//				case IPPROTO_TCP:
	//					fileout.write(reinterpret_cast<const char*>(&(*iter).ipPayload.tcpHeader), sizeof(struct tcphdr));
	//					//fileout.write(reinterpret_cast<const char*>(&(*iter).ipPayload.payload), (*iter).ipPayload.payloadsize);
	//					break;
	//				case IPPROTO_UDP:
	//					fileout.write(reinterpret_cast<const char*>(&(*iter).ipPayload.udpHeader), sizeof(struct udphdr));
	//					//fileout.write(reinterpret_cast<const char*>(&(*iter).ipPayload.payload), (*iter).ipPayload.payloadsize);
	//					break;
	//				case IPPROTO_ICMP:
	//					fileout.write(reinterpret_cast<const char*>(&(*iter).ipPayload.icmpHeader), sizeof(struct icmphdr));
	//					//fileout.write(reinterpret_cast<const char*>(&(*iter).ipPayload.payload), (*iter).ipPayload.payloadsize);
	//					break;
	//				default:
	//					//fileout.write(reinterpret_cast<const char*>(&(*iter).ipPayload.payload), (*iter).ipPayload.payloadsize);
	//					break;
	//			//	}
	//			}
	//		}
	//		fileout.close();
	//	}
}

/**
 *	Matches all packets with the appropriate flow.
 *	Returns true if file exists, otherwise returns false.
 *
 *	\param data		CPersist object containing all data.
 */
void find_match(CPersist & data) {

	vector<packet>::iterator plIter;
	for (plIter = data.packets.begin(); plIter != data.packets.end(); plIter++){

		uint8_t in = inflow;
		uint8_t q_in = q_infl;

		FlowHashKey6 mykey(&(plIter->dstIP), &(plIter->srcIP), &(plIter->dstPort), &(plIter->srcPort),
				&(plIter->protocol), &(in));
		FlowHashKey6 mykey_q(&(plIter->dstIP), &(plIter->srcIP), &(plIter->dstPort), &(plIter->srcPort),
				&(plIter->protocol), &(q_in));

		CFlowHashMultiMap6::iterator iter = data.flowHashMap->find(mykey);
		CFlowHashMultiMap6::iterator iter_q = data.flowHashMap->find(mykey_q);

		if (iter != data.flowHashMap->end()) {
			cflow fl = (*iter).second.get_flow();
			if ((fl.startMs - 1 < plIter->timestamp / 1000)
					&& (plIter->timestamp / 1000 < (fl.startMs + fl.durationMs + 1))) {
				if ((*iter).second.flow_incomplete()) {
					(*iter).second.add((*plIter));
				}
			}
		} else if (iter_q != data.flowHashMap->end()) {

			cflow fl = (*iter_q).second.get_flow();
			if ((fl.startMs - 1 < plIter->timestamp / 1000)
					&& (plIter->timestamp / 1000 < (fl.startMs + fl.durationMs + 1))) {
				if ((*iter).second.flow_incomplete()) {
					(*iter).second.add((*plIter));
				}
			}
		}
	}
}

/**
 *	Reads all packets from the pcap file 'pcap_filename'.
 *	If the packet is in the range of current cflow list
 *	the packet is matched with the currently loaded cflows.
 *
 *	\param pcap_filename	Filename of the pcap file to process
 *	\param data				CPersist object containing all data.
 */
void process_pcap(string pcap_filename, CPersist & data) {
	struct packet packet;

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
			if (!pco.next(p))
				break; // Quit if no more packets avaliable
			pcount++;

			// Get packet length from header, but limit it to capture length
			Packet::Length len =
					(p.get_length() > p.get_capture_length()) ?
							p.get_length() : p.get_capture_length();

			if (len < sizeof(struct ethhdr)) { // Is packet too small?
				cerr << "Found malformed packet.\n";
				continue;
			}

			Packet::Data const * pdata = p.get_data();

			struct ethhdr * ether_hdr = (struct ethhdr *) pdata;

			// Display packet header data if data link protocol is ethernet
			if (ntohs(ether_hdr->h_proto) == ETH_P_IP) { // Check if IPv4 packet

				// Process IPv4 packet
				// *******************

				if (len < (sizeof(struct ethhdr) + sizeof(struct iphdr))) { // Is packet too small?
					cerr << "Found malformed packet.\n";
					continue;
				}
				struct iphdr * ip_hdr = (struct iphdr *) (pdata
						+ sizeof(struct ethhdr));

				struct tcphdr * tcp_hdr = NULL;
				struct udphdr * udp_hdr = NULL;
				struct icmphdr * icmp_hdr = NULL;

				// Show transport layer protocol
				packet.init(ip_hdr->saddr, ip_hdr->daddr, ip_hdr->protocol);
				packet.ethHeader = *ether_hdr;
				packet.ipHeader = *ip_hdr;

				if ((sizeof(struct iphdr) < (packet.ipHeader.ihl * 4))
						&& data.verbose) {
					util::print_packet(packet);
				}
				switch (ip_hdr->protocol) {
				case IPPROTO_TCP:
					tcp_hdr = (struct tcphdr *) (pdata + sizeof(struct ethhdr)
							+ packet.ipHeader.ihl * 4);
					packet.srcPort = ntohs(tcp_hdr->source);
					packet.dstPort = ntohs(tcp_hdr->dest);
					packet.ipPayload.tcpHeader = *tcp_hdr;
					packet.packetsize = (sizeof(struct ethhdr)
							+ (sizeof(struct iphdr)) + sizeof(struct tcphdr));
					//packet.ipPayload.payloadsize = p.get_capture_length() - (sizeof(struct ethhdr)+packet.ipHeader.ihl*4+packet.ipPayload.tcpHeader.doff*4);
					//packet.ipPayload.payload = pdata+sizeof(struct ethhdr)+packet.ipHeader.ihl*4+packet.ipPayload.tcpHeader.doff*4;
					break;
				case IPPROTO_UDP:
					udp_hdr = (struct udphdr *) (pdata + sizeof(struct ethhdr)
							+ packet.ipHeader.ihl * 4);
					packet.srcPort = ntohs(udp_hdr->source);
					packet.dstPort = ntohs(udp_hdr->dest);
					packet.ipPayload.udpHeader = *udp_hdr;
					packet.packetsize = (sizeof(struct ethhdr)
							+ (sizeof(struct iphdr)) + sizeof(struct udphdr));
					//packet.ipPayload.payloadsize = p.get_capture_length() - (sizeof(struct ethhdr)+packet.ipHeader.ihl*4+sizeof(struct udphdr));
					//packet.ipPayload.payload = (pdata+sizeof(struct ethhdr)+sizeof(struct udphdr));
					break;
				case IPPROTO_ICMP:
					icmp_hdr = (struct icmphdr *) (pdata + sizeof(struct ethhdr)
							+ packet.ipHeader.ihl * 4);
					packet.ipPayload.icmpHeader = *icmp_hdr;
					packet.packetsize = (sizeof(struct ethhdr)
							+ (sizeof(struct iphdr)) + sizeof(struct icmphdr));
					//packet.ipPayload.payloadsize = p.get_capture_length() - (sizeof(struct ethhdr)+packet.ipHeader.ihl*4+sizeof(struct icmphdr));
					//packet.ipPayload.payload = (pdata+sizeof(struct ethhdr)+packet.ipHeader.ihl*4+sizeof(struct icmphdr));
					break;
				default:
					packet.packetsize = (sizeof(struct ethhdr)
							+ packet.ipHeader.ihl * 4);
					//packet.ipPayload.payloadsize = p.get_capture_length() - (sizeof(struct ethhdr)+packet.ipHeader.ihl*4);
					//packet.ipPayload.payload = (pdata+sizeof(struct ethhdr)+packet.ipHeader.ihl*4);
					break;
				}

				packet.timestamp = p.get_seconds() * 1000000
						+ p.get_miliseconds(); //get_miliseconds returns microseconds and not milliseconds
				packet.ipHeader.ihl = 0x45; // Set the ipV4 Header size to 20 Bytes. IP Options are ignored.
				packet.actualsize = p.get_length();

				data.packets.push_back(packet);
			}
		}

	} catch (PcapError & pcerror) {

		cerr << "ERROR: " << pcerror.what() << endl;

	} catch (...) {
		cout << "ERROR: unknown exception occurred.\n";
	}
}

/**
 *	Get the number of flows and packets for each rule. Save them
 *	to the file 'flowcount.csv' and print the total number
 *	of flows to standard output.
 *
 *	\param data		CPersist object containing all data.
 */
void get_flow_count(CPersist &data) {
	ofstream out;
	string statfile_flowcount = "flowcount.csv";
	util::open_outfile(out, statfile_flowcount);
	out << "Rule;Flow-Count;Packet-Count" << endl;
	long total_rflows = 0;
	for (int i = 0; i <= data.c.get_rule_count(); i++) {
		int flowcount = 0;
		int packetcount = 0;
		cout << "Rule: " << i << endl;
		//		int interval = 2;
		for (CFlowHashMultiMap6::iterator it = data.flowHashMap->begin();
				it != data.flowHashMap->end(); it++) {
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


uint8_t get_tcp_flags(tcphdr const &tcp_hdr) {
	return *(((uint8_t *) &(tcp_hdr.ack_seq)) + 5);
}

int get_icmp_type(const packet p) {
	return p.ipPayload.icmpHeader.type;
}

int get_icmp_code(const packet p) {
	return p.ipPayload.icmpHeader.code;
}

/**
 * Checks if the flag sequence from a given packet sequence is valid
 *
 * @param packets
 * @return TRUE if valid sequence, else FALSE
 */
bool valid_flag_sequence_check(vector<packet> packets) {

	int counter = 0;
	uint8_t flag_sequence[5] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t tcp_flags;

	//Fill flag sequence with 5 first packets from flow
	for (vector<packet>::iterator it = packets.begin();
			it != packets.end() && counter < 5; ++it) {
		tcp_flags = get_tcp_flags((*it).ipPayload.tcpHeader);

		flag_sequence[counter] = tcp_flags;
		counter++;
	}

	//Check if flag sequence is valid. One single SYN is considered a SYN-Scan and therefore an invalid flag sequence.
	if (flag_sequence[0] == 0x02 && flag_sequence[1] == 0x02
			&& flag_sequence[2] == 0x02 && flag_sequence[3] == 0x02
			&& flag_sequence[4] == 0x02)
		return true; // 5 syn flags
	if (flag_sequence[0] == 0x02 && flag_sequence[1] == 0x02
			&& flag_sequence[2] == 0x02 && flag_sequence[3] == 0x02
			&& flag_sequence[4] == 0x00)
		return true; // 4 syn flags
	if (flag_sequence[0] == 0x02 && flag_sequence[1] == 0x02
			&& flag_sequence[2] == 0x02 && flag_sequence[3] == 0x00
			&& flag_sequence[4] == 0x00)
		return true; // 3 syn flags
	if (flag_sequence[0] == 0x02 && flag_sequence[1] == 0x02
			&& flag_sequence[2] == 0x00 && flag_sequence[3] == 0x00
			&& flag_sequence[4] == 0x00)
		return true; // 2 syn flags

	return false;
}




void flow_validation(CPersist & data, bool verbose, int rule_no) {
	switch (rule_no) {
		case 4:
			for (CFlowHashMultiMap6::iterator it = data.flowHashMap->begin();
					it != data.flowHashMap->end(); ++it) {

				if ((*it).second.get_flow().prot == IPPROTO_TCP) {
					if (get_tcp_flags(
							(*it).second.get_packets().begin()->ipPayload.tcpHeader)
							== 0x02 && (*it).second.get_packets().size() == 1) { //SYN Scan

						data.scan5_validation_flow_count["TP :SYN Scan"]++;

						if (verbose) {
							cout << "True Positive: Flow assigned to Rule " << rule_no
									<< " and is SYN Scan" << endl;
						}
					} else {

						data.scan5_validation_flow_count["Unknown"]++;
					}
				} else if (get_tcp_flags(
						(*it).second.get_packets().begin()->ipPayload.tcpHeader)
						== 0x29) { //X-Mas Tree Scan (URG+PSH+FIN)

					data.scan5_validation_flow_count["TP: X-Mas Tree Scan"]++;

					if (verbose) {
						cout << "True Positive: Flow assigned to Rule " << rule_no
								<< " and is X-Mas Tree Scan" << endl;
					}
				} else if (get_tcp_flags(
						(*it).second.get_packets().begin()->ipPayload.tcpHeader)
						== 0x01) { //FIN Scan

					data.scan5_validation_flow_count["TP: Fin Scan"]++;

					if (verbose) {
						cout << "True Positive: Flow assigned to Rule " << rule_no
								<< " and is FIN Scan" << endl;
					}
				} else if (get_tcp_flags(
						(*it).second.get_packets().begin()->ipPayload.tcpHeader)
						== 0x00) { //Null Scan

					data.scan5_validation_flow_count["TP: Null Scan"]++;

					if (verbose) {
						cout << "True Positive: Flow assigned to Rule " << rule_no
								<< " and is Null Scan" << endl;
					}
				}
			}
			break;
		case 8:
		case 9:
		case 10:
			for (CFlowHashMultiMap6::iterator it =
					data.flowHashMap->begin();
					it != data.flowHashMap->end(); ++it) {
				if ((*it).second.get_flow().prot == IPPROTO_ICMP) {
					for (vector<packet>::const_iterator it2 =
							(*it).second.get_packets().begin();
							it2 != (*it).second.get_packets().end(); ++it2) {
						if (get_icmp_type(*it2) == 8 || get_icmp_type(*it2) == 13
								|| get_icmp_type(*it2) == 15
								|| get_icmp_type(*it2) == 17
								|| get_icmp_type(*it2) == 35
								|| get_icmp_type(*it2) == 37) {
							data.backsc_validation_flow_count["FP: ICMP Request"]++;
						} else {
							data.backsc_validation_flow_count["Unknown"]++;
						}
					}
				} else if ((*it).second.get_flow().prot == IPPROTO_TCP) {
					bool synpkt;
					for (vector<packet>::const_iterator it2 =
							(*it).second.get_packets().begin();
							it2 != (*it).second.get_packets().end(); it2++) {
						if (get_tcp_flags((*it2).ipPayload.tcpHeader) == 0x02)
							synpkt = true;
					}
					if (synpkt) {
						data.backsc_validation_flow_count["FP: SYN Packet"]++;
					} else {
						data.backsc_validation_flow_count["Unknown"]++;
					}
				} else if ((*it).second.get_flow().prot == IPPROTO_UDP) {
					bool empty_packet = false;
					for (vector<packet>::const_iterator it2 =
							(*it).second.get_packets().begin();
							it2 != (*it).second.get_packets().end(); it2++) {
						if ((*it2).packetsize == (*it2).actualsize) { // UDP Packet has no payload
							empty_packet = true;
						}
					}
					if (empty_packet) {
						data.backsc_validation_flow_count["FP: Empty UDP Packet"]++;
					} else {
						data.backsc_validation_flow_count["Unknown"]++;
					}
				}
			}
			break;
		case 14:
			//rule15

			for (CFlowHashMultiMap6::iterator it = data.flowHashMap->begin();
					it != data.flowHashMap->end(); ++it) {
				bool var_eq_0 = true; //Variation of packet size over entire flow
				uint32_t prev_packet_size =
						(*(*it).second.get_packets().begin()).packetsize;
				for (vector<packet>::const_iterator it2 = (*it).second.get_packets().begin();
						it2 != (*it).second.get_packets().end(); it2++) {
					if ((*it2).packetsize != prev_packet_size) {
						var_eq_0 = false;
					}
				}
				if (var_eq_0) {
					data.sbenign_validation_flow_count["FP: Packet size var == 0"]++;
				}
				if ((*(*it).second.get_packets().begin()).protocol == IPPROTO_TCP) {
					for (vector<packet>::const_iterator it2 =
							(*it).second.get_packets().begin();
							it2 != (*it).second.get_packets().end(); it2++) {
						if (!valid_flag_sequence_check((*it).second.get_packets())) {
							data.sbenign_validation_flow_count["FP: Invalid flag seq"]++;
						} else {
							data.sbenign_validation_flow_count["Unknown"]++;
						}
					}
				}
			}
			break;
		case 5:
		case 6:
		case 7:

			//Other Malign
			for (CFlowHashMultiMap6::iterator it =
					data.flowHashMap->begin();
					it != data.flowHashMap->end(); ++it) {
				if ((*(*it).second.get_packets().begin()).protocol == IPPROTO_TCP) {
					for (vector<packet>::const_iterator it2 =
							(*it).second.get_packets().begin();
							it2 != (*it).second.get_packets().end(); it2++) {
						if (!valid_flag_sequence_check(
								(*it).second.get_packets())) {
							data.sbenign_validation_flow_count["TP: Invalid flag seq"]++;
						} else {
							data.sbenign_validation_flow_count["Unknown"]++;
						}
					}
				} else if ((*(*it).second.get_packets().begin()).protocol
						== IPPROTO_UDP) {
					bool empty_packet = false;
					for (vector<packet>::const_iterator it2 =
							(*it).second.get_packets().begin();
							it2 != (*it).second.get_packets().end(); it2++) {
						if (((*it2).actualsize == (*it2).packetsize)) { // UDP Packet has no payload
							empty_packet = true;
						}
					}
					if (empty_packet) {
						data.sbenign_validation_flow_count["TP: Empty UDP Packet"]++;
					} else {
						data.sbenign_validation_flow_count["Unknown"]++;
					}
				}
			}
			break;
	}
}

void write_validation_stats(CPersist & data){
	ofstream out;

	string filename = "scan5_validation_stats.csv";
	util::open_outfile(out, filename);
	out << "Type;Count" << endl;
	map<string, int>::iterator iter;
	for (iter = data.scan5_validation_flow_count.begin(); iter != data.scan5_validation_flow_count.end(); iter++){
		out << (*iter).first << ";" << (*iter).second << endl;
	}
	out.close();
	filename = "sbenign_validation_stats.csv";
	util::open_outfile(out, filename);
	out << "Type;Count" << endl;
	for (iter = data.sbenign_validation_flow_count.begin(); iter != data.sbenign_validation_flow_count.end(); iter++){
		out << (*iter).first << ";" << (*iter).second << endl;
	}
	out.close();
	filename = "backsc_validation_stats.csv";
	util::open_outfile(out, filename);
	out << "Type;Count" << endl;
	for (iter = data.backsc_validation_flow_count.begin(); iter != data.backsc_validation_flow_count.end(); iter++){
		out << (*iter).first << ";" << (*iter).second << endl;
	}
	out.close();
	filename = "othermal_validation_stats.csv";
	util::open_outfile(out, filename);
	out << "Type;Count" << endl;
	for (iter = data.othermal_validation_flow_count.begin(); iter != data.othermal_validation_flow_count.end(); iter++){
		out << (*iter).first << ";" << (*iter).second << endl;
	}
	out.close();

}

int main(int argc, char **argv) {

	const char * Date = __DATE__;
	const char * time = __TIME__;

	cout
			<< "Evaluation of One-Way Flows V 0.1 (c) E. Glatz, N. Bigler, M. Fisler (build: ";
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
	bool analysis = false;

	string date("");

	int i;
	while ((i = getopt(argc, argv, "f:r:c:p:tahd:vV")) != -1) {
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
		case 'h':
			usage(argv[0], cout);
			exit(0);
			break;
		case 'd':
			date = optarg;
			if (date.size() != 8) {
				cerr
						<< "\n\nERROR: invalid date string. Option -d expects a date of form YYYYMMSS.\n";
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
		if (util::getSamples(list_filename, files) != 0) {
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
		cerr << "ERROR: input file name " << files[0]
				<< " does not end in .gz as it should.\n\n";
		exit(1);
	}
	string date_time;
	if (date.size() > 0) {
		date_time = date + ".0000";
	} else {
		date_time = files[0].substr(pos - 15, 13); // Extract date/time as YYYYMMDD.hhmm
	}
	CPersist data(date_time, verbose, verbose2, test, rules_filename);

	// 2. Execute command
	// ******************

	vector<string> pcap_files;

	if (pcap_filelist.size() > 0) {
		if (util::getSamples(pcap_filelist, pcap_files) != 0) {
			cerr << "ERROR: could not read files in " + list_filename << endl;
			exit(1);
		}
	} else {
		cerr << "ERROR: no pcap file_list provided" << endl;
		usage(argv[0], cerr);
	}
	data.flowHashMap = new CFlowHashMultiMap6();

	for (size_t i = 0; i < pcap_files.size(); i++) {
		if (pcap_files.size() > 1) {
			cout << pcap_files[i] << endl;
		}
		process_pcap(pcap_files[i], data);
		if (files.size() > 1) {
			cout << "Processing file:\n";
		}
		string rulename = pcap_files[i].substr(pcap_files[i].find_last_of("_")+1,pcap_files[i].find_last_of(".")-pcap_files[i].find_last_of("_")-1);
		cout << "Rulename: " << rulename << endl;
		for (size_t j = 0; j < files.size(); j++) {
			if (files.size() > 1) {
				cout << files[j] << endl;
			}
			process_interval(files[j], data, j, rulename);
			find_match(data);
		}
		flow_validation(data,verbose, data.c.get_rule_number(rulename));
		data.flowHashMap->clear();
		data.packets.clear();
	}
	write_validation_stats(data);
}
