/* \file HashMap.cpp
 * \brief HashMap implementation file
 * 
 * Copyright (c) 2008, Bernhard Tellenbach 
 *
 * Author: Bernhard Tellenbach  (bernhard.tellenbach@gmail.com) 
 * 
 * Distributed under the Gnu Public License version 2 or the modified
 * BSD license (see file COPYING
 *
 */
#include <cstdio>
#include <string.h>
#include "HashMap.h"

/* *************************************************************
 * Key type HashKeyGeneric: Arbitrary lengt key (slow)         *
 * *************************************************************/

HashKeyGeneric::HashKeyGeneric(char* buf, uint8_t len) {
	key = NULL;
	length = len;
	key = new char[length];
	memcpy(key, buf, length);
}

HashKeyGeneric::~HashKeyGeneric() {
	delete[] key;
}

size_t HashKeyGeneric::size() const {
	return length;
}

HashKeyGeneric::HashKeyGeneric(const HashKeyGeneric &b) {
	key = new char[b.length];
	memcpy(key, b.key, b.length);
	length = b.length;
}

std::string HashKeyGeneric::printkey() const {
	char buf[length * 4 + 1];
	for (unsigned int i = 0; i < length; i++) {
		sprintf(&(buf[i * 4]), "0x%02ix", key[i]);
	}
	return std::string(buf);
}

/* *************************************************************
 * Key type HashKeyIPv4: IPv4 key                              *
 * *************************************************************/

HashKeyIPv4::HashKeyIPv4(uint32_t * ip) {
	memcpy(key, ip, 4);
}

HashKeyIPv4::~HashKeyIPv4() {

}

size_t HashKeyIPv4::size() const {
	return 4;
}

HashKeyIPv4::HashKeyIPv4(const HashKeyIPv4 &b) {
	memcpy(key, b.key, 4);
}

std::string HashKeyIPv4::printkey() const {
	char tmpip[5];
	inet_ntop(AF_INET, key, tmpip, 5);
	return std::string(tmpip);
}

/* *************************************************************
 * Key type HashKeyIPv4: IPv4Pair key                          *
 * *************************************************************/

HashKeyIPv4Pair::HashKeyIPv4Pair(uint32_t * ip1, uint32_t * ip2) {
	*((uint32_t *) (&(key[0]))) = *ip1;
	*((uint32_t *) (&(key[4]))) = *ip2;
}

HashKeyIPv4Pair::~HashKeyIPv4Pair() {

}

size_t HashKeyIPv4Pair::size() const {
	return 8;
}

HashKeyIPv4Pair::HashKeyIPv4Pair(const HashKeyIPv4Pair &b) {
	memcpy(key, b.key, 8);
}

std::string HashKeyIPv4Pair::printkey() const {
	char buf[128];
	char tmpip1[20];
	char tmpip2[20];
	inet_ntop(AF_INET, &(key[0]), tmpip1, 20);
	inet_ntop(AF_INET, &(key[4]), tmpip2, 20);
	sprintf(buf, "%s %s", tmpip1, tmpip2);
	return std::string(buf);
}

/* *************************************************************
 * Key type HashKeyIPv6: IPv6 key                              *
 * *************************************************************/

HashKeyIPv6::HashKeyIPv6(char * ip) {
	memcpy(key, ip, 16);
}

HashKeyIPv6::~HashKeyIPv6() {

}

size_t HashKeyIPv6::size() const {
	return 16;
}

HashKeyIPv6::HashKeyIPv6(const HashKeyIPv6 &b) {
	memcpy(key, b.key, 16);
}

std::string HashKeyIPv6::printkey() const {
	char tmpip[21];
	inet_ntop(AF_INET6, key, tmpip, 21);
	return std::string(tmpip);
}

/* *************************************************************
 * Key type HashKeyIPv4_3T: IPv4 Three-Tuple key               *
 * *************************************************************/

HashKeyIPv4_3T::HashKeyIPv4_3T(uint32_t * IP, uint8_t * protocol,
		uint16_t * port) {
	*((uint32_t *) (&(key[0]))) = *IP;
	*((uint8_t *) (&(key[4]))) = *protocol;
	*((uint16_t *) (&(key[5]))) = *port;
}

HashKeyIPv4_3T::~HashKeyIPv4_3T() {

}

size_t HashKeyIPv4_3T::size() const {
	return 7;
}

HashKeyIPv4_3T::HashKeyIPv4_3T(const HashKeyIPv4_3T &b) {
	memcpy(key, b.key, 7);
}

std::string HashKeyIPv4_3T::printkey() const {
	char buf[128];
	char tmpip[20];
	inet_ntop(AF_INET, key, tmpip, 20);
	sprintf(buf, "%u - %s:%u %s:%u (%u)", *((uint8_t *) (&(key[4]))), tmpip,
			*((uint16_t *) (&(key[5]))));
	return std::string(buf);
}

/* *************************************************************
 * Key type HashKeyIPv4_4T: IPv4 Four-Tuple key                *
 * *************************************************************/

HashKeyIPv4_4T::HashKeyIPv4_4T(uint32_t * localIP, uint32_t * remoteIP,
		uint8_t * protocol, uint8_t * direction) {
	*((uint32_t *) (&(key[0]))) = *localIP;
	*((uint32_t *) (&(key[4]))) = *remoteIP;
	*((uint8_t *) (&(key[8]))) = *protocol;
	*((uint16_t *) (&(key[9]))) = *direction;
}

HashKeyIPv4_4T::~HashKeyIPv4_4T() {

}

size_t HashKeyIPv4_4T::size() const {
	return 10;
}

HashKeyIPv4_4T::HashKeyIPv4_4T(const HashKeyIPv4_4T &b) {
	memcpy(key, b.key, 10);
}

std::string HashKeyIPv4_4T::printkey() const {
	char buf[128];
	char tmpip_src[20];
	char tmpip_dst[20];
	inet_ntop(AF_INET, key, tmpip_src, 20);
	inet_ntop(AF_INET, &(key[4]), tmpip_dst, 20);

	// protocol:localIP - remoteIP, direction
	sprintf(buf, "%u: %s - %s, %u", *((uint8_t *) (&(key[8]))), tmpip_src,
			*((uint16_t *) (&(key[8]))), tmpip_dst,
			*((uint16_t *) (&(key[10]))), *((uint8_t *) (&(key[9]))));
	return std::string(buf);
}

/* *************************************************************
 * Key type HashKeyIPv4_5T: IPv4 Five-Tuple key                *
 * *************************************************************/

HashKeyIPv4_5T::HashKeyIPv4_5T(uint32_t * srcIP, uint32_t * dstIP,
		uint16_t * srcPort, uint16_t * dstPort, uint8_t * protocol) {
	*((uint32_t *) (&(key[0]))) = *srcIP;
	*((uint32_t *) (&(key[4]))) = *dstIP;
	*((uint16_t *) (&(key[8]))) = *srcPort;
	*((uint16_t *) (&(key[10]))) = *dstPort;
	*((uint8_t *) (&(key[12]))) = *protocol;

}

HashKeyIPv4_5T::~HashKeyIPv4_5T() {

}

size_t HashKeyIPv4_5T::size() const {
	return 13;
}

HashKeyIPv4_5T::HashKeyIPv4_5T(const HashKeyIPv4_5T &b) {
	memcpy(key, b.key, 13);
}

std::string HashKeyIPv4_5T::printkey() const {
	char buf[128];
	char tmpip_src[20];
	char tmpip_dst[20];
	inet_ntop(AF_INET, key, tmpip_src, 20);
	inet_ntop(AF_INET, &(key[4]), tmpip_dst, 20);
	sprintf(buf, "%u - %s:%u %s:%u", *((uint8_t *) (&(key[12]))), tmpip_src,
			*((uint16_t *) (&(key[8]))), tmpip_dst,
			*((uint16_t *) (&(key[10]))));
	return std::string(buf);
}

/* *************************************************************
 * Key type HashKeyIPv4_6T: IPv4 Six-Tuple key                 *
 * *************************************************************/

HashKeyIPv4_6T::HashKeyIPv4_6T(uint32_t * srcIP, uint32_t * dstIP,
		uint16_t * srcPort, uint16_t * dstPort, uint8_t * protocol,
		uint8_t * tos) {
	*((uint32_t *) (&(key[0]))) = *srcIP;
	*((uint32_t *) (&(key[4]))) = *dstIP;
	*((uint16_t *) (&(key[8]))) = *srcPort;
	*((uint16_t *) (&(key[10]))) = *dstPort;
	*((uint8_t *) (&(key[12]))) = *protocol;
	*((uint8_t *) (&(key[13]))) = *tos;

}

HashKeyIPv4_6T::~HashKeyIPv4_6T() {

}

size_t HashKeyIPv4_6T::size() const {
	return 14;
}

HashKeyIPv4_6T::HashKeyIPv4_6T(const HashKeyIPv4_6T &b) {
	memcpy(key, b.key, 14);
}

std::string HashKeyIPv4_6T::printkey() const {
	char buf[128];
	char tmpip_src[20];
	char tmpip_dst[20];
	inet_ntop(AF_INET, key, tmpip_src, 20);
	inet_ntop(AF_INET, &(key[4]), tmpip_dst, 20);
	sprintf(buf, "%u - %s:%u %s:%u (%u)", *((uint8_t *) (&(key[12]))),
			tmpip_src, *((uint16_t *) (&(key[8]))), tmpip_dst,
			*((uint16_t *) (&(key[10]))), *((uint8_t *) (&(key[13]))));
	return std::string(buf);
}

/* *************************************************************
 * Key type HashKeyIPv4_7T: IPv4 Seven-Tuple key               *
 * *************************************************************/

HashKeyIPv4_7T::HashKeyIPv4_7T(uint32_t * srcIP, uint32_t * dstIP,
		uint16_t * srcPort, uint16_t * dstPort, uint8_t * protocol,
		uint8_t * tos, uint8_t * dir) {
	*((uint32_t *) (&(key[0]))) = *srcIP;
	*((uint32_t *) (&(key[4]))) = *dstIP;
	*((uint16_t *) (&(key[8]))) = *srcPort;
	*((uint16_t *) (&(key[10]))) = *dstPort;
	*((uint8_t *) (&(key[12]))) = *protocol;
	*((uint8_t *) (&(key[13]))) = *tos;
	*((uint8_t *) (&(key[14]))) = *dir;
}

HashKeyIPv4_7T::~HashKeyIPv4_7T() {

}

size_t HashKeyIPv4_7T::size() const {
	return 15;
}

HashKeyIPv4_7T::HashKeyIPv4_7T(const HashKeyIPv4_7T &b) {
	memcpy(key, b.key, 15);
}

std::string HashKeyIPv4_7T::printkey() const {
	char buf[128];
	char tmpip_src[20];
	char tmpip_dst[20];
	inet_ntop(AF_INET, key, tmpip_src, 20);
	inet_ntop(AF_INET, &(key[4]), tmpip_dst, 20);
	sprintf(buf, "%u - %s:%u %s:%u (%u) (%u)", *((uint8_t *) (&(key[12]))),
			tmpip_src, *((uint16_t *) (&(key[8]))), tmpip_dst,
			*((uint16_t *) (&(key[10]))), *((uint8_t *) (&(key[13]))),
			*((uint8_t *) (&(key[14]))));
	return std::string(buf);
}
