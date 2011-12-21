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

class CFlowlist {
private:
	std::string filename; ///< Name of input file	

	uint32_t crc32; ///< CRC32 value stored in GZIP file trailer
	unsigned int ISIZE; ///< Size of the original (uncompressed) input data mpdulo 2^32

	struct cflow * flowlist; ///< List containing all flows
	int flow_count; ///< Count of flows kept in flowlist

	long bytes; ///< Total bytes
	uint64_t start_time; ///< Start time of oldest flow [ms] 
	uint64_t end_time; ///< Start time of newest flow

	int cur_flow; ///< Index to flowlist entry containing next flow to be read by get_next_flow()
				  ///< Set to -1 when at end of list or not initialized by get_first_flow()

public:
	CFlowlist(std::string filename);
	~CFlowlist();

	void read_flows();
	struct cflow * get_first_flow();
	struct cflow * get_next_flow();
	struct cflow * get_flow_at(int i) {
		return &(flowlist[i]);
	}

	struct cflow * get_flowlist() {
		return flowlist;
	}
	;
	int get_flow_count() {
		return flow_count;
	}
	std::string & get_filename() {
		return filename;
	}

private:
	void init();
	bool read_flow(boost::iostreams::filtering_istream & infs,
			struct cflow * cf);

};

#endif /* FLOWLIST_H_ */

