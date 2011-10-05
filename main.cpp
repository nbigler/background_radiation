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
#include <netinet/in.h>			// IP protocol types

#include "HashMap2.h"
#include "cflow.h"



bool debug = false;

using namespace std;
using namespace pcappp;

// Hash key & map for storing flows
// ********************************
// key = 6-tuple (5-tuple + direction)
// data = references to flowlist records
//
typedef HashKeyIPv4_6T FlowHashKey6;
typedef hash_map<HashKeyIPv4_6T, struct cflow, HashFunction<HashKeyIPv4_6T>, HashFunction<HashKeyIPv4_6T> > FlowHashMap6;
void print_flow(std::pair<HashKeyIPv4_6T, cflow> hash);
u_int16_t endian_swap(u_int16_t _x);

int main(int argc, char **argv) {


	FlowHashMap6 * flowHM6 = new FlowHashMap6();
	FlowHashMap6::iterator iter;
	FlowHashMap6::iterator iter_inverse;
	FlowHashMap6::iterator iter_biflow;

	struct cflow flow;
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
		cout << "File name is: " << filename << endl;

		int major = pco.get_major_version();
		int minor = pco.get_minor_version();
		cout << "File format used is: " << major << "." << minor << endl;

		if (pco.is_swapped()) {
			cout << "Capture data byte order differs from byte order used on this system.\n";
		} else {
			cout << "Capture data byte order complies with byte order used on this system.\n";
		}

		DataLink dl = pco.get_datalink();
		cout << "Data link code: " << dl.get_description() << endl;

		if (dl.get_type() == DataLink::EN10MB) {
			cout << "INFO: data link type is standard Ethernet (10 MB up).\n";
		} else {
			cout << "INFO: data link type is NOT Ethernet. Type code is: " << dl.get_type() << ".\n";
			cout << "\nAll done.\n\n";
			return 0;
		}

		unsigned int slen = pco.get_snaplen();
		cout << "Snap length: " << slen << endl << endl;

		cout << "Packet header details (for IPv4 packets):\n";

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

				uint32_t netmask;
				inet_pton(AF_INET, "172.20.0.0", &netmask);

				// Show transport layer protocol
				switch (ip_hdr->protocol) {
				case IPPROTO_TCP:
					tcp_hdr = (struct tcphdr *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					if ((ip_hdr->saddr&netmask) == netmask){
						flow.init(ip_hdr->saddr, endian_swap(tcp_hdr->source), ip_hdr->daddr, endian_swap(tcp_hdr->dest), ip_hdr->protocol, outflow);
					}else{
						flow.init(ip_hdr->daddr, endian_swap(tcp_hdr->dest), ip_hdr->saddr, endian_swap(tcp_hdr->source), ip_hdr->protocol, inflow);
					}
					break;
				case IPPROTO_UDP:
					udp_hdr = (struct udphdr *)(pdata+sizeof(struct ethhdr)+sizeof(struct iphdr));
					if ((ip_hdr->saddr&netmask) == netmask){
						flow.init(ip_hdr->saddr, endian_swap(udp_hdr->source), ip_hdr->daddr, endian_swap(udp_hdr->dest), ip_hdr->protocol, outflow);
					}else{
						flow.init(ip_hdr->daddr, endian_swap(udp_hdr->dest), ip_hdr->saddr, endian_swap(udp_hdr->source), ip_hdr->protocol, inflow);
					}
					break;
				default:
					if ((ip_hdr->saddr&netmask) == netmask){
						flow.init(ip_hdr->saddr, 0, ip_hdr->daddr, 0, ip_hdr->protocol, outflow);
					}else{
						flow.init(ip_hdr->daddr, 0, ip_hdr->saddr, 0, ip_hdr->protocol, inflow);
					}
					break;
				}
				flow.tos_flags = ip_hdr->tos;

				// Check if current flow is already contained in hash map
				FlowHashKey6 mykey(&(flow.localIP), &(flow.remoteIP), &(flow.localPort),
					&(flow.remotePort), &(flow.prot), &(flow.dir));

				uint8_t inv_flow;
				if (flow.dir == inflow) {
					inv_flow = outflow;
				}else {
					inv_flow = inflow;
				}
				FlowHashKey6 mykey_inverse(&(flow.localIP), &(flow.remoteIP), &(flow.localPort),
					&(flow.remotePort), &(flow.prot), &(inv_flow));

				uint8_t bi_flow = biflow;

				FlowHashKey6 mykey_biflow(&(flow.localIP), &(flow.remoteIP), &(flow.localPort),
					&(flow.remotePort), &(flow.prot), &(bi_flow));

				iter = flowHM6->find(mykey);
				iter_inverse = flowHM6->find(mykey_inverse);
				iter_biflow = flowHM6->find(mykey_biflow);

				if (iter == flowHM6->end()) {
					if (iter_inverse == flowHM6->end()){
						if (iter_biflow == flowHM6->end()) {
							flow.startMs = p.get_seconds()*1000 + p.get_miliseconds()/1000; //get_miliseconds() returns microseconds not miliseconds
							flow.dOctets = p.get_capture_length();
							flow.dPkts = 1;
							(*flowHM6)[mykey] = flow;
						}else{
							(*flowHM6)[mykey_biflow].durationMs = p.get_seconds()*1000 + p.get_miliseconds()/1000 - (*flowHM6)[mykey_biflow].startMs;
							(*flowHM6)[mykey_biflow].dOctets = p.get_capture_length() + (*flowHM6)[mykey_biflow].dOctets;
							(*flowHM6)[mykey_biflow].dPkts = (*flowHM6)[mykey_biflow].dPkts + 1;
						}
					}else {
						(*flowHM6)[mykey_inverse].flowtype = biflow;
						(*flowHM6)[mykey_inverse].durationMs = p.get_seconds()*1000 + p.get_miliseconds()/1000 - (*flowHM6)[mykey_inverse].startMs;
						(*flowHM6)[mykey_inverse].dOctets = p.get_capture_length() + (*flowHM6)[mykey_inverse].dOctets;
						(*flowHM6)[mykey_inverse].dPkts = (*flowHM6)[mykey_inverse].dPkts + 1;
					}

				} else {
					(*flowHM6)[mykey].durationMs = p.get_seconds()*1000 + p.get_miliseconds()/1000 - (*flowHM6)[mykey].startMs;
					(*flowHM6)[mykey].dOctets = p.get_capture_length() + (*flowHM6)[mykey].dOctets;
					(*flowHM6)[mykey].dPkts = (*flowHM6)[mykey].dPkts + 1;
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
	for_each(flowHM6->begin(),flowHM6->end(),print_flow);
}

u_int16_t endian_swap(u_int16_t _x){
	u_int16_t x = _x;
	x = (x>>8) | (x<<8);
	return x;
}

void print_flow(std::pair<HashKeyIPv4_6T, cflow> hash){
	cflow flow = hash.second;
	char localIP[INET_ADDRSTRLEN];
	char remoteIP[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(flow.localIP), localIP, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(flow.remoteIP), remoteIP, INET_ADDRSTRLEN);
	cout << "Source IP: " << localIP << "\tSource Port: " << flow.localPort << endl;
	cout << "Destination IP: " << remoteIP << "\t Remote Port: " << flow.remotePort << endl;
	cout << "ToS-Flags: " << flow.tos_flags << endl;
	cout << "Flow-Size (Byte): " << flow.dOctets << endl;
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
	cout << "Start Time: " << flow.startMs << "ms \tDuration: " << flow.durationMs << "ms" << endl;
	cout << "-----------------------" << endl;
}


