/*
 * main.cpp
 *
 *  Created on: Oct 1, 2011
 *      Author: bigli
 */
#include <cstring>
#include <string>

#include <pcap++.h>

// Library functions, e.g. ntoh()
#include <arpa/inet.h>

// Protocol header definitions
#include <linux/if_ether.h>	// Ethernet header, ethernet protocol types
#include <netinet/ip.h>			// IP header
#include <netinet/tcp.h>		// TCP header
#include <netinet/udp.h>		// UDP header
#include <netinet/ip_icmp.h>	// ICMP header
#include <netinet/in.h>			// IP protocol types

#include "HashMap2.h"
#include "libs/utils.h"
#include "libs/flow.h"



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

//void print_flow(std::pair<HashKeyIPv4_6T, flow> hash);
void print_cvs(std::pair<HashKeyIPv4_6T, flow> hash);
u_int16_t endian_swap(u_int16_t _x);
uint8_t get_tcp_flags(tcphdr const &tcp_hdr);


int main(int argc, char **argv) {


	FlowHashMap6 * flowHM6 = new FlowHashMap6();
	FlowHashMap6::iterator iter;
	FlowHashMap6::iterator iter_inverse;
	FlowHashMap6::iterator iter_biflow;

	struct flow flow;
	memset((void *)&flow, 0,sizeof(flow));

	if (argc != 2) {
		cerr << "ERROR: no pcap file name specified on command line.\n";
		return 1;
	}
	// Open file for packet reading
	int pcount = 0;	// Packet counter
	try {
		PcapOffline pco(argv[1]);

		// Get some general infos from file
		string filename = pco.get_filename();
		//cout << "File name is: " << filename << endl;

		int major = pco.get_major_version();
		int minor = pco.get_minor_version();
		//cout << "File format used is: " << major << "." << minor << endl;

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

		unsigned int slen = pco.get_snaplen();
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
					flow.payload.push_back(payload);
					break;
				case IPPROTO_UDP:
					udp_hdr = (struct udphdr *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					flow.localPort = endian_swap(udp_hdr->source);
					flow.remotePort = endian_swap(udp_hdr->dest);
					payload.udpHeader = udp_hdr;
					payload.payload = (char * )(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr));
					flow.payload.push_back(payload);
					break;
				case IPPROTO_ICMP:
					icmp_hdr = (struct icmphdr *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					payload.icmpHeader = icmp_hdr;
					payload.payload = (char * )(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr));
					flow.payload.push_back(payload);
					break;
				default:
					payload.payload = (char *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					break;
				}

				// Check if current flow is already contained in hash map
				FlowHashKey6 mykey(&(flow.localIP), &(flow.remoteIP), &(flow.localPort),
					&(flow.remotePort), &(flow.protocol), &(flow.flowtype));

				uint8_t inv_flow;
				if (flow.flowtype == inflow) {
					inv_flow = outflow;
				}else {
					inv_flow = inflow;
				}
				FlowHashKey6 mykey_inverse(&(flow.localIP), &(flow.remoteIP), &(flow.localPort),
					&(flow.remotePort), &(flow.protocol), &(inv_flow));

				uint8_t bi_flow = biflow;

				FlowHashKey6 mykey_biflow(&(flow.localIP), &(flow.remoteIP), &(flow.localPort),
					&(flow.remotePort), &(flow.protocol), &(bi_flow));

				iter = flowHM6->find(mykey);
				iter_inverse = flowHM6->find(mykey_inverse);
				iter_biflow = flowHM6->find(mykey_biflow);

				if (iter == flowHM6->end()) {
					if (iter_inverse == flowHM6->end()){
						if (iter_biflow == flowHM6->end()) {
							flow.startMs = p.get_seconds()*1000000 + p.get_miliseconds(); //get_miliseconds() returns microseconds not milliseconds
							flow.dOctets = p.get_capture_length();
							flow.dPkts = 1;
							(*flowHM6)[mykey] = flow;
						}else{
							(*flowHM6)[mykey_biflow].durationMs = p.get_seconds()*1000000 + p.get_miliseconds() - (*flowHM6)[mykey_biflow].startMs;
							(*flowHM6)[mykey_biflow].dOctets = p.get_capture_length() + (*flowHM6)[mykey_biflow].dOctets;
							(*flowHM6)[mykey_biflow].dPkts = (*flowHM6)[mykey_biflow].dPkts + 1;
							(*flowHM6)[mykey_biflow].payload.push_back(flow.payload.at(0));
						}
					}else {
						(*flowHM6)[mykey_inverse].flowtype = biflow;
						(*flowHM6)[mykey_inverse].durationMs = p.get_seconds()*1000000 + p.get_miliseconds() - (*flowHM6)[mykey_inverse].startMs;
						(*flowHM6)[mykey_inverse].dOctets = p.get_capture_length() + (*flowHM6)[mykey_inverse].dOctets;
						(*flowHM6)[mykey_inverse].dPkts = (*flowHM6)[mykey_inverse].dPkts + 1;
						(*flowHM6)[mykey_inverse].payload.push_back(flow.payload.at(0));
					}

				} else {
					(*flowHM6)[mykey].durationMs = p.get_seconds()*1000000 + p.get_miliseconds() - (*flowHM6)[mykey].startMs;
					(*flowHM6)[mykey].dOctets = p.get_capture_length() + (*flowHM6)[mykey].dOctets;
					(*flowHM6)[mykey].dPkts = (*flowHM6)[mykey].dPkts + 1;
					(*flowHM6)[mykey].payload.push_back(flow.payload.at(0));
				}
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

u_int16_t endian_swap(u_int16_t _x){
	u_int16_t x = _x;
	x = (x>>8) | (x<<8);
	return x;
}

void print_cvs(std::pair<HashKeyIPv4_6T, flow> hash){
	flow flow = hash.second;
	char localIP[INET_ADDRSTRLEN];
	char remoteIP[INET_ADDRSTRLEN];
	util::ipV4AddressToString(flow.localIP,localIP,INET_ADDRSTRLEN);
	util::ipV4AddressToString(flow.remoteIP,remoteIP,INET_ADDRSTRLEN);
	for (int i = 0; i < flow.dPkts; i++){
		uint8_t tcp_header = *(((uint8_t *)&(flow.payload[i].tcpHeader->ack_seq))+5);
		cout <<  localIP << "; " << flow.localPort << "; " << remoteIP << "; " << flow.remotePort << "; ";
		cout << util::ipV4ProtocolToString(flow.protocol) << "; 0x" << hex << (int) flow.tos_flags << dec << "; 0x" << hex << (int) tcp_header << dec << "; " << flow.dOctets << "; " << flow.dPkts << "; ";
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
	cout << "; " << fixed << (flow.startMs/(double) 1000);  // Unix-Timestamp
	cout << "; " << flow.durationMs << endl;
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

uint8_t get_tcp_flags(tcphdr const &tcp_hdr) {
	return *(((uint8_t *)&(tcp_hdr.ack_seq))+5);
}

