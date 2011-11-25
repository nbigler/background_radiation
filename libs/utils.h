#ifndef UTIL_H_
#define UTIL_H_

/**
  *	\file utils.h
  *	\brief Include file for utility functions.
  *
  * 	Copyright (c) 2010, Eduard Glatz 
  *
  * 	Author: Eduard Glatz  (eglatz@tik.ee.ethz.ch) 
  */

#include <fstream>
#include <iostream>
#include <set>
#include <vector>

#include "cflow.h"
#include "packet.h"

namespace util {
	void open_outfile(std::ofstream & outfs, std::string ofname);
	void reopen_outfile(std::ofstream & outfs, std::string ofname);
	void open_infile(std::ifstream & infs, std::string ifname);
	void ipV4AddressToString(uint32_t addr, char * dst, size_t dst_len);
	const std::string& ipV4ProtocolToString(uint8_t prot);
	void record2String(struct cflow * record, char * out);
	void swap_endians(struct cflow & pflow);
	void seconds2date_ISO8601(uint32_t seconds, std::string & s);
	std::string pformat(int x, int min_fieldsize);
	std::string pformat(long x, int min_fieldsize);
	std::string & flowtype2string(flow_type_t flowtype);
	void print_packet(const struct packet & pck);
	void print_flow(const struct cflow & fl);

	int getSamples(std::string filename, std::vector<std::string> & files);
};


#endif

