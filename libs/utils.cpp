/**
  *	\file utils.cpp
  *	\brief Utility functions.
  *
  * 	Copyright (c) 2010, Eduard Glatz 
  *
  * 	Author: Eduard Glatz  (eglatz@tik.ee.ethz.ch) 
  */

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <cstdlib>
#include <cstring>
#include <ctime>

#include <sstream>

#include <boost/date_time/posix_time/posix_time.hpp>

#include "utils.h"
#include "cflow.h"	// For magic codes (struct cflow)


using namespace std;


namespace util {

/**
  *	Open file for output. Discard any contents if it already exists.
  *
  *	\param outfs : output stream (out)
  *	\param ofname : name of output file (in)
  */
void open_outfile(ofstream & outfs, string ofname) {
	try {
		outfs.open(ofname.c_str(), ios::out | ios::trunc);
	}
	catch (...) {
		cerr << "ERROR: opening output file " << ofname << " failed.\nTerminating.\n";
		throw;
	}		
}



/**
  *	Re-Open file for output. Append new contents to existing file.
  *
  *	\param outfs : output stream (out)
  *	\param ofname : name of output file (in)
  */
void reopen_outfile(ofstream & outfs, string ofname) {
	try {
		outfs.open(ofname.c_str(), ios::out | ios::app);
	}
	catch (...) {
		cerr << "ERROR: re-opening output file " << ofname << " failed.\nTerminating.\n";
		throw;
	}		
}



/**
  *	Open file for (binary) input.
  *
  *	\param outfs : output stream (out)
  *	\param ofname : name of output file (in)
  */
void open_infile(ifstream & infs, string ifname) {
	struct stat statbuf;
	if (stat(ifname.c_str(), &statbuf)==-1) {
   	cout << "ERROR: opening input file " << ifname << endl;
		perror("ERROR: stat()");
		char buf[256];
		getcwd(buf, 256);
		cout << "Current working directory is: " << buf << endl;
		throw;
	}
	infs.exceptions(ifstream::eofbit | ifstream::failbit | ifstream::badbit);
	try {	
		infs.open(ifname.c_str(), ios::in | ios_base::binary);
	}
	catch (ifstream::failure & e) {
   	cout << "Exception opening file " << ifname << endl;
		if (infs.fail()) cout << "failbit set\n";
		if (infs.eof())  cout << "eofbit set\n";
		if (infs.bad())  cout << "badbit set\n";
		if (infs.good()) cout << "goodbit set\n";
		throw;
	}
	catch (...) {
		cout << "\n\nERROR: unknown error while opening input file " << ifname << "\n\n";
		throw;
	}
	infs.exceptions(ios::goodbit);
}



/** 
 * \brief Returns the dotted decimal string representation of the IPV4 address in addr.
 *
 * \param addr IPV4 address in host-byte-order
 * \param dst Pointer to the pre-allocated destination character array
 * \param dst_len Length of the pre-allocated destination character array
 * \return void
 */
void ipV4AddressToString(uint32_t addr, char * dst, size_t dst_len) {
	//unsigned long int naddr = htonl(addr);
	inet_ntop(AF_INET, &addr, dst, dst_len);
}


	
/** 
 * \brief Returns the IP protocol as string. E.g. UDP, TCP, ...
 *
 * \param prot IP V4 protocol number
 * \return string IP protocol name
 */
const string& ipV4ProtocolToString(uint8_t prot) { 
	switch (prot) {
	case IPPROTO_ICMP:
		static const string icmp = "ICMP";
		return icmp;
	case IPPROTO_IGMP:
		static const string igmp = "IGMP";
		return igmp;
	case IPPROTO_TCP:
		static const string tcp = "TCP";
		return tcp;
	case IPPROTO_UDP:
		static const string udp = "UDP";
		return udp;
	case IPPROTO_IPV6:
		static const string ipv6 = "IPv6";
		return ipv6;
	case IPPROTO_RSVP:
		static const string rsvp = "RSVP";
		return rsvp;
	case IPPROTO_GRE:
		static const string gre = "GRE";
		return gre;
	case 94: // Remark: not defined in in.h
		static const string ipip = "IPIP";
		return ipip;
	default:
		static char protoname[20];
		sprintf(protoname, "prot%d", prot);
		static const string unknown(protoname);
		return unknown;
	}
}


/**
  *	Print record contents in human readable form to console.
  *
  *	\param record	A single flow record.
  *	\param out Output stream to be used.
  */
void record2String(struct cflow * record, char * out)
{
	// Start time
	time_t tt = (time_t)(record->startMs/1000);
	struct tm ts;
	localtime_r(&tt, &ts);

	// IP addresses
	static char local[16];
	static char remote[16];
	ipV4AddressToString(record->localIP, local, sizeof(local));
	ipV4AddressToString(record->remoteIP, remote, sizeof(remote));

	char dirviz[6] = { "-----" };

	switch (record->dir) {
		case biflow:	
		case inflow:
			dirviz[0] = '<';
			break;
		case (outflow | unibiflow):
			dirviz[0] = '*';
			break;
		default:
			break;
	}

	switch (record->dir) {
		case biflow:	
		case outflow:
			dirviz[4] = '>';
			break;
		case (inflow | unibiflow):
			dirviz[4] = '*';
			break;
		default:
			break;
	}

	char ip_padding1[] = "        ";
	ip_padding1[15-strlen(local)] = '\0';
	char ip_padding2[] = "        ";
	ip_padding2[15-strlen(remote)] = '\0';

	sprintf(
			out,
			"%-4s: %s"
			"%s%s:%05d ->%s%s:%05d, "
			"AS:%05d->%05d,"
			"%8u Byte,%5u Pkts, "
			"start=%02d:%02d:%02d.%03lld, "
			"dur= %d.%03d s, ToS=%03d, magic=%d",
			ipV4ProtocolToString(record->prot).c_str(), dirviz,
			ip_padding1, local, record->localPort, ip_padding2, remote, record->remotePort, 
			record->AS.local, record->AS.remote,
			(unsigned int) record->dOctets, record->dPkts,
			ts.tm_hour, ts.tm_min, ts.tm_sec, (long long int) record->startMs % 1000,
			record->durationMs / 1000, record->durationMs % 1000, record->tos_flags, record->magic);
}


/**
  *	swap_endians - Converts the ip-address from the cflow struct
  *	from network byte order to host byte order.
  *
  *	\param pflow cflow struct to convert
  *
  */
void swap_endians(struct cflow & pflow)
{
    pflow.localIP = ntohl(pflow.localIP);
    pflow.remoteIP = ntohl(pflow.remoteIP);
    //pflow.localPort = ntohs(pflow.localPort);
    //pflow.remotePort = ntohs(pflow.remotePort);
}



/**
  *	seconds2date_ISO8601 - converts time from UTC-1900-seconds to extended "YYYY.MM.DD-HR:MIN:SEC" UTC date format.
  *	This format is useful to display date/time values on the console.
  *
  *	\param seconds	: time in unix seconds
  *	\param s : result string for date/time	
  */
void seconds2date_ISO8601(uint32_t seconds, string & s)
{
	time_t tt = (time_t)seconds;
	struct tm ts;
	gmtime_r(&tt, &ts);
	char * tmp = NULL;

	// ISO8601 demands: YYYY-MM-DD hh:mm:ssZ (Z stands for "UTC" or "Zulu-time", respectively)
	asprintf(&tmp, "%04d-%02d-%02d %02d:%02d:%02dZ", 1900 + ts.tm_year,
		1+ts.tm_mon, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);
	s = tmp;
	free(tmp);
}




/**
  *	Format a number for pretty output.
  *
  *	If required then leading spaces are added.
  *	Number is formatted by groups of three digits separated by single quotes.
  *	Note: this function is not reentrant (due to local static variable)  
  *
  *	\param 	x to be formatted
  *	\param 	fieldsize Minimum field size to use.
  */
string pformat(int x, int min_fieldsize)
{
	#define dbg false

	stringstream ss;
	ss << x;

	ss.seekg (0, ios::end);
   int numdigits = ss.tellg();
   ss.seekg (0, ios::beg);

	int numsigns=0;
	if (x<0) numsigns=1; // Negative numbers have a leading minus sign

	// Calculate number of commas
	int numcommas = (numdigits-numsigns) / 3;

	if (((numdigits-numsigns) % 3)==0) numcommas--;	// Suppress comma if no digit on the left of it

	// Calculate number of leading spaces
	int numspaces = min_fieldsize - numdigits - numcommas;
	if (dbg) {
		if (numspaces<0) { numspaces=0; cerr << "INFO: field size exceeded.\n"; }
	}

	static string s;
	s.clear();
	for (int i=0; i<numspaces; i++) s += " ";
	if (numsigns>0) {
		char buf[2];
		ss.read(buf, 1);
		buf[1]=0;
		s += buf;
	}

	int leadingdigits = (numdigits-numsigns) % 3;

	if (dbg) {
		cout << "x=" << x << ", min_fieldsize=" << min_fieldsize << ", numdigits=" << numdigits << ", numsigns=" << numsigns;
		cout << ", numspaces=" << numspaces<< ". leadingdigits=" << leadingdigits << ", numcommas=" << numcommas << endl;
	}
	// Output leading digits
	if (leadingdigits > 0) {
		char buf[80];
		ss.read(buf, leadingdigits);
		buf[leadingdigits]=0;
		s += buf;
	}

	// Update remaining number of digits
	numdigits -= leadingdigits;

	// Output remaining digits as groups of three 
	for (int j=numdigits/3; j>0; j--) {
		char buf[6];
		ss.read(buf, 3);
		buf[3]=0;
		if (j<numdigits/3 || leadingdigits>0) s += "'";
		s += (char *)buf;
	}		

	return s;
}	


/**
  *	Format a number for pretty output.
  *
  *	If required then leading spaces are added.
  *	Number is formatted by groups of three digits separated by single quotes.
  *	Note: this function is not reentrant (due to local static variable)  
  *
  *	\param 	x to be formatted
  *	\param 	fieldsize Minimum field size to use.
  */
string pformat(long x, int min_fieldsize)
{
	#define dbg false

	stringstream ss;
	ss << x;

	ss.seekg (0, ios::end);
   int numdigits = ss.tellg();
   ss.seekg (0, ios::beg);

	int numsigns=0;
	if (x<0) numsigns=1; // Negative numbers have a leading minus sign

	// Calculate number of commas
	int numcommas = (numdigits-numsigns) / 3;

	if (((numdigits-numsigns) % 3)==0) numcommas--;	// Suppress comma if no digit on the left of it

	// Calculate number of leading spaces
	int numspaces = min_fieldsize - numdigits - numcommas;
	if (dbg) {
		if (numspaces<0) { numspaces=0; cerr << "INFO: field size exceeded.\n"; }
	}

	static string s;
	s.clear();
	for (int i=0; i<numspaces; i++) s += " ";
	if (numsigns>0) {
		char buf[2];
		ss.read(buf, 1);
		buf[1]=0;
		s += buf;
	}

	int leadingdigits = (numdigits-numsigns) % 3;

	if (dbg) {
		cout << "x=" << x << ", min_fieldsize=" << min_fieldsize << ", numdigits=" << numdigits << ", numsigns=" << numsigns;
		cout << ", numspaces=" << numspaces<< ". leadingdigits=" << leadingdigits << ", numcommas=" << numcommas << endl;
	}
	// Output leading digits
	if (leadingdigits > 0) {
		char buf[80];
		ss.read(buf, leadingdigits);
		buf[leadingdigits]=0;
		s += buf;
	}

	// Update remaining number of digits
	numdigits -= leadingdigits;

	// Output remaining digits as groups of three 
	for (int j=numdigits/3; j>0; j--) {
		char buf[6];
		ss.read(buf, 3);
		buf[3]=0;
		if (j<numdigits/3 || leadingdigits>0) s += "'";
		s += (char *)buf;
	}		

	return s;
}	



/**
  *	Provides a descriptive text for a passed flow type.
  *
  *	\param flowtype	Flow direction type as defined by format "struct cflow" (see cflow.h)
  *	\return String that describes given flow type
  */
string & flowtype2string(flow_type_t flowtype)
{
	static string s;

	switch (flowtype) {
		case 1:  s="outflow"; break;
		case 2:  s="inflow";  break;
		case 3:  s="uniflow"; break;
		case 4:  s="biflow";  break;
		case 8:  s="unibifl"; break;
		case 7:  s="allflow"; break;
		case 12: s="okflow";  break;
		default: 
			static char dirX[] = "? =  ";
			char msd = 0x30 + flowtype / 10;
			char lsd = 0x30 + flowtype % 10;
			dirX[3] = msd;
			dirX[4] = lsd;
			s = dirX;
			break;
	}
	return s;
}



/**
  *	Reads file names from input file and returns them through a file name vector.
  *	For each file name it is checked if file exists and is accessible.
  *
  *	\param filename	Name of input text file containing one file name per line
  *	\param files		Returns names of all files found in input file
  */
int getSamples(string filename, vector<string> & files)
{
	if (filename.size() > 0) {
		// Check if file exists
	   struct stat fileStatus;
	   int iretStat = stat(filename.c_str(), &fileStatus);
	   if (iretStat==-1) { 
			cerr << "\nERROR: " << filename << " does not exist or is not accessible.\n"; 
			perror("stat()"); 
			cerr << "Check file name.\n\n";
			char buf[256];
			getcwd(buf, 256);
			cout << "Current working directory is: " << buf << endl;
			exit(1);
		 }

		// Open input file
		ifstream infs;
		infs.exceptions(ifstream::eofbit | ifstream::failbit | ifstream::badbit);
		try {	
			infs.open(filename.c_str(), ios::in | ios_base::binary);
		}
		catch (ifstream::failure & e) {
			cout << "Exception opening file " << filename << endl;
			if (infs.fail()) cout << "failbit set\n";
			if (infs.eof())  cout << "eofbit set\n";
			if (infs.bad())  cout << "badbit set\n";
			if (infs.good()) cout << "goodbit set\n";
			throw;
		}
		catch (...) {
			cout << "\n\nERROR: unknown error while opening input file " << filename << "\n\n";
			throw;
		}
		infs.exceptions(ios::goodbit);

		// Fetch names from list
		do {
			char fname[256];
			infs.getline(fname, 256);
			if (infs.good() && strlen(fname)>0) {
				// Put file name into appropriate list
				string fileName = fname;
				files.push_back(fname);
			}
		} while (infs.good());

		// Check if all files given in list exist
		vector<string>::iterator it;
		for (it=files.begin(); it!=files.end(); it++) {
			struct stat fileStatus;
			int iretStat = stat(it->c_str(), &fileStatus);
			if (iretStat==-1) { 
				cerr << "\nERROR: file " << *it << " does not exist or is not accessible.\n"; 
				perror("stat()"); 
				return -1; 
			}
		}
		cout << "Files read:"<< files.size() << endl;
	} else {
		cout << "ERROR: missing filename.\n";
		exit(1);
	}

	return 0;
}

void print_packet(const packet & pck) {
	static char local[16];
	static char remote[16];
	ipV4AddressToString(pck.localIP, local, sizeof local);
	ipV4AddressToString(pck.remoteIP, remote, sizeof remote);
	cout << "Packet: " << local << ":" << pck.localPort << ";\t" << remote << ":" << pck.remotePort << ";" << static_cast<int>(pck.protocol) << endl;
}

int count_occurrence_of_char(const char c, const string s) {
	int count = 0;
	for(unsigned int i=0; i < s.size(); i++) {
		if(s.at(i) == c) ++count;
	}
	return count;
}

using namespace boost::posix_time;

/*uint64_t snort_date_time_to_epoch(string snort_date_time) {
	//Format of the Snort Date-Time String: 10/18-17:16:04.231133 (10-18-2011; 17h16m04.231133s)
	if(count_occurrence_of_char('/', snort_date_time) < 1) return 0.0;
	if(count_occurrence_of_char('/', snort_date_time) >= 1 && count_occurrence_of_char('/', snort_date_time) <=2) {
		if(count_occurrence_of_char('/', snort_date_time) == 1) {
			snort_date_time.insert(0, "2011-"); //Assume Year is 2011 if not present
		}
		for(string::iterator it = snort_date_time.begin(); it != snort_date_time.end(); ++it) {
			if(*it == '/') snort_date_time.replace(it, it+1, "-");
		}
	}
	ptime t = time_from_string(snort_date_time);
	ptime start = time_from_string("1979-01-01 00:00:00.0");
	time_duration dur = t - start;
	time_t epoch = dur.total_microseconds();

	return static_cast<uint64_t>(epoch);
}*/



} // Namespace util

