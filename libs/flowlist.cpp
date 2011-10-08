/**
  *	\file flowlist.cpp
  *	\brief Flowlist handling.
  *
  * 	Copyright (c) 2010, Eduard Glatz 
  *
  * 	Author: Eduard Glatz  (eglatz@tik.ee.ethz.ch) 
  *
  *	tab width 3
  */



#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fstream>
#include <iostream>
#include <set>

#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/device/file.hpp>

#include <boost/crc.hpp>  // for boost::crc_32_type

#include "cflow.h"
#include "utils.h"
#include "flowlist.h"


using namespace std;

const bool debug = false;


/*CFlowlist::CFlowlist(string filename)
{
	this->filename = filename;
	flowlist = NULL;
	flow_count = 0;
	cur_flow = -1;
	flowlist = NULL;

	if (filename.size() > 0) {	// Treat zero length filename as dummy file
		// Sanity check: does input file exist?
		struct stat statbuf;
		if (stat(filename.c_str(), &statbuf)==-1) {
			perror("ERROR: stat()");
			cerr << "ERROR: check input file " << filename << " and try again.\n";
			exit(1);
		}
		//cout << "Input file contains " << util::pformat(statbuf.st_size, 11) << " bytes.\n";

		// Sanity check II: check gzip format
		init();
	}
}*/

CFlowlist::CFlowlist(string filename, FlowHashMap6 * flowHM6){
	this->flowHM6 = flowHM6;
	this->filename = filename;
	createFile();
}


CFlowlist::~CFlowlist()
{
	delete flowHM6;
}




/**
  *	Check if file has a valid GZIP file format.
  *	If yes, then extract CRC32 value and byte count of uncompressed data. 
  *
  */
void CFlowlist::init()
{
	ifstream infs0;
//	cout << "Checking input file: " << filename << endl;
	cout.flush();
	util::open_infile(infs0, filename);
	// Verify that it is a GZIP file (check GZIP metadata)
	uint8_t HDR[3];	// First three bytes of header
	infs0.read((char *)HDR, 3);	// Get first three bytes
	unsigned int ID1 = HDR[0];
	unsigned int ID2 = HDR[1];
	unsigned int CM  = HDR[2];
	if (ID1==0x1f && ID2==0x8b && CM==8) {
	//	cout << "\nFile recognized to have GZIP format according to RFC1952 (magic numbers comply).\n";
	} else {
		cerr << "\nERROR: input file \"" << filename << "\" does not comply with GZIP-format according to RFC1952.\n";
		cerr << "One or more incorrect magic numbers ID1 (expected: 0x1f) = 0x" << hex << ID1;
		cerr << ", ID2 (expected: 0x8b) = 0x" << hex << ID2 << dec << ", CM (expected: 8) = " << CM << endl;
		exit(1);
	}
	// Ok, file has valid GZIP format
	infs0.seekg (0, ios::end);
	int filesize = infs0.tellg();
	//cout << "File size is: " << filesize << " bytes.\n";
	infs0.seekg (-8, ios::end);
	// Now fetch CRC32 code and initial file size from file trailer
	infs0.read((char *)&crc32, 4);
	uint32_t CRC32 = crc32;
//	cout << "CRC32 stored in file trailer is: " << hex << CRC32 << dec << ".\n";
	uint32_t isize=0;	
	infs0.read((char *)&isize, 4);
	ISIZE = isize;
	//cout << "Input file size stored in file trailer is: " << ISIZE << " bytes.\n"; 
	infs0.close();
}

void CFlowlist::createFile() {
	ofstream outfs;
	util::open_outfile(outfs, filename);
	uint8_t HDR[3];
	HDR[0] = 0x1f;
	HDR[1] = 0x8b;
	HDR[2] = 8;
	outfs.write((char *) HDR, 3); //write first three bits (gz-signature)
	outfs.close();
}


/**
  *	Read flows from file into memory-based flowlist.
  *
  */
/*void CFlowlist::read_flows()
{
	if (filename.size()==0) { 
		cout << "Nothing to read (dummy filename of zero length).\n";
		return;
	}

	start_time = -1;	// Set unsigned variable to it's highest value (artificial wrap around)
	end_time = 0; // Set to earliest (unix) time possible

	// Open up a stream chain
	boost::iostreams::filtering_istream in;
	// Add stream compressor
	in.push(boost::iostreams::gzip_decompressor());

	// Open input file and link it to stream chain
	boost::iostreams::file_source infs(filename);
	if (!infs.is_open()) {
		cerr << "ERROR: could not open file source \"" << filename << "\".\n"; 
		exit(1);
	}
	in.push(infs);
	cout << "Reading file " << filename << ":\n";

	// Allocate flow list based on original (uncompressed) file size stored in GZIP file trailer.
	const int maxnum_flows = 1 + ISIZE / sizeof(struct cflow);	// Allow 1 more for overflow check
	flowlist = new struct cflow[maxnum_flows]; //Here we allocate 

	bool nl_flag = false;
	// fetch first flow
	bool ok = read_flow(in, &flowlist[0]);
	flow_count = 1;
	// Loop through all flows of input file
	while (ok) {
		if (flow_count > maxnum_flows) {
			cerr << "ERROR: flow list overflow.\n";
			cerr << "Calculated flow count "<< maxnum_flows << " from input file isize " << ISIZE << " is exceeded.\n\n";
			exit(1);
		}

		// Show progress on console
		if ((flow_count % 100000) == 0) { nl_flag = true; cout << "."; cout.flush(); }

		// Fetch next flow
		ok = read_flow(in, &flowlist[flow_count]);
		if (ok) flow_count++;

	} // while(ok): processing of flow
	if (nl_flag) cout << endl;


	// Close current input file (and stream compressor)
	in.pop();

	cout << "Successfully read " << util::pformat(flow_count, 9) << " flows from file \"" << filename << "\".\n";

	string stime;
	util::seconds2date_ISO8601(start_time/1000, stime);
	//cout << "Earliest flow read starts at: " << stime << ".\n";
	util::seconds2date_ISO8601(end_time/1000, stime);
	//cout << "Latest flow read starts at: " << stime << ".\n";


	double MBytes = (double)bytes / (1024.0*1024.0);
	cout.precision(2);
	cout.setf(ios::fixed,ios::floatfield); 
	//cout << "Total byte count is " << util::pformat(bytes, 11) << " (" << MBytes << " MB).\n";
//	cout << "Compression factor is " << (double)(flow_count*sizeof(struct cflow))/(double)statbuf.st_size << "\n";
	double sizeMB = ((double)(flow_count*sizeof(struct cflow)))/(1024.0*1024.0);
//	cout << "Flowlist size is " << sizeMB << " MB.\n";
//	cout << "Per flow magic number verified: ";
	if (in.eof()) {
	//	cout << "file ends correctly by end of last flow.\n";
	} else {
		// Loop ended due to an error
		cerr << "\n\nERROR in FlowList(): read error on input data\n\n--> terminating program with status=1.\n\n";
		exit(1);
	}

	if (debug) {
		cout << "Contents read from input file:\n";
		int cnt = (flow_count>100) ? 100 : flow_count;
		char text[256];
		for (int i=0; i<flow_count; i++) {
			util::record2String(&flowlist[i], text);
			cout << text << endl;
			if (i>=cnt) {
				cout << "\n... more than 100 flows (not shown)\n";
				break;
			}
		}
	}

	//cout << "All done.\n\n";
}*/

void CFlowlist::write_flows(){
	// Open up a stream chain
	boost::iostreams::filtering_ostream out;

	// Add stream compressor
	out.push(boost::iostreams::gzip_compressor());

	// Open output file and link it to stream chain
	boost::iostreams::file_sink outfs(filename);
	std::fstream myfile(filename.c_str(), std::ios::out|std::ios::app);
	if (!outfs.is_open()) {
		cerr << "ERROR: could not open file source \"" << filename << "\".\n";
		exit(1);
	}
	out.push(outfs);
	cout << "Writing file " << filename << ":\n";

	for (FlowHashMap6::iterator it = flowHM6->begin(); it!=flowHM6->end(); it++) {
		write_flow(out, & it->second);
	}
	uint8_t crc[4];
	crc[3]=0xFF;
	crc[2]=0xEE;
	crc[1]=0xDD;
	crc[0]=0xCC;
	crc32 = 0xFFEEDDCC;
	ISIZE = sizeof(struct cflow) * flowHM6->size();

	uint8_t size[4];
	size[0] = (uint8_t) ISIZE;
	size[1] = (uint8_t) (ISIZE >> 8);
	size[2] = (uint8_t) (ISIZE >> 16);
	size[3] = (uint8_t) (ISIZE >> 24);

	out.pop();

	ofstream outstr;
	util::reopen_outfile(outstr, filename);
	outstr.write((char *) crc, 4);
	outstr.write((char *) size, 4);
	outstr.flush();
	outstr.close();

}

/**
  *	Read a single flow from a file containing GZIP-compressed flow data encoded in the "cflow record format".
  *	Data read from file is checked for correct record size and per flow magic number.
  *
  *	\param infs Input stream including a GZIP-decompressor.
  *	\param cf Flow record filled with data read from file.
  *	\return TRUE if per-flow record magic number is okay (false otherwise)
  */

void CFlowlist::write_flow(boost::iostreams::filtering_ostream & outfs, struct cflow * cf) {
	outfs.write((char *) cf, sizeof(struct cflow));
}













