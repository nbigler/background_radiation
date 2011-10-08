#ifndef FLOWLIST_H_
#define FLOWLIST_H_
/**
  *	\file flowlist.h
  *	\brief Include file for flowlist handling.
  *
  * 	Copyright (c) 2010, Eduard Glatz 
  *
  * 	Author: Eduard Glatz  (eglatz@tik.ee.ethz.ch) 
  *
  *	tab width 3
  */

#include <boost/iostreams/filtering_stream.hpp>
#include "cflow.h"
#include "../HashMap2.h"

typedef HashKeyIPv4_6T FlowHashKey6;
typedef hash_map<HashKeyIPv4_6T, struct cflow, HashFunction<HashKeyIPv4_6T>, HashFunction<HashKeyIPv4_6T> > FlowHashMap6;

class CFlowlist {
private:
	std::string filename;		///< Name of input file	

	uint32_t crc32;				///< CRC32 value stored in GZIP file trailer
	unsigned int ISIZE;			///< Size of the original (uncompressed) input data mpdulo 2^32

	FlowHashMap6 * flowHM6;	///< List containing all flows
	int flow_count;				///< Count of flows kept in flowlist

	long bytes;						///< Total bytes
	uint64_t	start_time;			///< Start time of oldest flow [ms] 
	uint64_t end_time;			///< Start time of newest flow

	int cur_flow;					///< Index to flowlist entry containing next flow to be read by get_next_flow()
										///< Set to -1 when at end of list or not initialized by get_first_flow()

public:
	CFlowlist(std::string filename, FlowHashMap6 * flowHM6);
	~CFlowlist();

	void write_flows();


private:
	void init();
	void createFile();
	void write_flow(boost::iostreams::filtering_ostream & outfs, struct cflow * cf);

};

#endif /* FLOWLIST_H_ */

