/** 
 * \file HashMap.h
 * \brief Header file that defines keys and hashfunction for use with the SGI hash_map
 * 
 * Copyright (c) 2008, Bernhard Tellenbach 
 *
 * Author: Bernhard Tellenbach  (bernhard.tellenbach@gmail.com) 
 * 
 * 
 *\section general_hmap General Remarks on the SGI hash_map
 * Pros of the SGI hash_map vs. the NetflowVxPlusPlus HashedTable:
 *  - Interface to hash_map objects is the same as the interface to STL map Objects
 *  - Deletion of elements while iterating over the elements requires no special treatment
 *  - Faster, if the size of the hash table is not known or if it grows/shrinks many times during operation
 *  - Template based. No typecasts required to read elements. Type specified during construction.
 *
 * <br>Cons of the SGI hash_map vs. the NetflowVxPlusPlus HashedTable:
 * - If there is a need for a generic key (of arbitrary length), the hash_map can be slower than the HashedTable.
 *
 * <b> WARNING: </b> Even though it is possible to define the element type to be of non-pointer type, this should not be
 * used unless your element type is a basic number type (int, long,...). The reason is, that an insert operation makes
 * <b> a copy </b> of the element (if it is a pointer type, it just makes a copy of the pointer!). Therefore, if your
 * element size is bigger than a pointer (more than 4 (32-bit system) or 8 (64-bit system) bytes), you would introduce
 * memory copy-overhead! However, using pointer types is less comfortable than using non-pointer types because the 
 * hash_map would take care of the deletion of the elements. If you use pointer types, you have to delete the elements YOURSELF!
 * (see example code).
 * 
 * \section hmap_hashkeys Custom Hash Key Types
 * If you need key types other than those already specified in this header file, and if you do not want to use the 
 * HashKeyGeneric because of its performance penalty, you can create your own key type. This is straight forward since
 * the only thing that your new Key Class has to do is to implement the following interface (see one of the key types already defined in this header file as example):
 *
 * \section specific_hmap Examples
 * - <b>Example 1: </b>  Creation, use and deletion of a hash_map with entries of type 'unsigned long long' (basic number type) and HashKeyIPv4Addr keys.
 * \code 
#include "HashMap.h"
#include <iostream>
#include <sys/types.h>

#define NUM_ELEMENTS  10000000

using namespace std;

typedef HashKeyIPv4_6T MyHashKey;
typedef hash_map<HashKeyIPv4_6T, uint32_t , HashFunction<HashKeyIPv4_6T>,HashFunction<HashKeyIPv4_6T> > HashMap;

int main() {
	uint32_t dstAddr = 0;
	uint16_t dstPort = 0;
	uint16_t srcPort = 0;
	uint8_t protocol = 0;
	uint8_t tos = 0;

	try{

	//insert NUM_ELEMENTS. Key is 'counting' source address and other key fields set to zero
	HashMap * myHashMap = new HashMap();
	for (uint32_t i = 0; i< NUM_ELEMENTS;i++){
		MyHashKey mykey(&i, &dstAddr, &srcPort, &dstPort, &protocol, &tos);
		(*myHashMap)[mykey]=i;
	}

	//searching for elements (here, we search for all inserted elements!)	
	HashMap::iterator iter;
	uint32_t found = 0;
	for (uint32_t i = 0; i < NUM_ELEMENTS; i++) {
		MyHashKey mykey(&i, &dstAddr, &srcPort, &dstPort, &protocol, &tos);
		iter = myHashMap->find(mykey);
		if(iter!=myHashMap->end()){
			//access and print the key:
			//  cout << (iter->first).printkey() << "\n";
			//access the element: 
			//   cout << "Stored uint32_t value is:"<< (iter->second) << "\n";
			found++;
		}
	}
	if(found != NUM_ELEMENTS){
		throw("ERROR: Not all inserted elements found! Aborting....\n");
	}

	//deleting elements while iterating over the hash table
	//NOTE 1: Elements are of basic non-pointer type. The memory used is 
	//        automatically freed when deleting the element.
	//NOTE 2: Deletion of an hash table entry must NOT be done using
	//        the iterator itself -> memory exception. You must advance the
	//        iterator before deleting the entry!
	
	HashMap::iterator  iter_end = myHashMap->end();
	HashMap::iterator  iter_tmp;
	iter = myHashMap->begin();
	uint32_t deleted = 0;
	while(iter!=iter_end) {
		iter_tmp = iter;
		++iter;
		myHashMap->erase(iter_tmp);		
		deleted++;
	}
	if(deleted != NUM_ELEMENTS){
		cout << deleted << "\n";
		throw("ERROR: Not all inserted elements could be deleted! Aborting....\n");
	} else {
		cout << "Example SUCCESSFULLY completed!\n";
	} 
	delete myHashMap;
	}catch (char const * e){
		cout<< "Caught Exception: " << e << "\n";
	}

}
 * \endcode
 * 
 * - <b>Example 2: </b> Creation, use and deletion of a hash_map with entries of type 'MyObject *' (pointer type) and HashKeyIPv4_6T keys
 * \code 
#include "HashMap.h"
#include <iostream>
#include <sys/types.h>

#define NUM_ELEMENTS  10000000

using namespace std;

class MyObject {
	private:
	uint32_t myIntfield;
	public:
	char info[16];
	//constructor of myObject
	MyObject(uint32_t myint){
		myIntfield = myint;
		for(int i=0; i<16; i++){
			info[i]=0;
		}
	}
	//destructor of myObject
	~MyObject(){
		
	}	
};

typedef HashKeyIPv4_6T MyHashKey;
typedef hash_map<HashKeyIPv4_6T, MyObject * , HashFunction<HashKeyIPv4_6T>,HashFunction<HashKeyIPv4_6T> > HashMap;

int main() {
	uint32_t dstAddr = 0;
	uint16_t dstPort = 0;
	uint16_t srcPort = 0;
	uint8_t protocol = 0;
	uint8_t tos = 0;

	try{

	//insert NUM_ELEMENTS. Key is 'counting' source address and other key fields set to zero
	HashMap * myHashMap = new HashMap();
	for (uint32_t i = 0; i< NUM_ELEMENTS;i++){
		MyHashKey mykey(&i, &dstAddr, &srcPort, &dstPort, &protocol, &tos);
		(*myHashMap)[mykey]=new MyObject(i);
	}

	//searching for elements (here, we search for all inserted elements!)	
	HashMap::iterator iter;
	uint32_t found = 0;
	for (uint32_t i = 0; i < NUM_ELEMENTS; i++) {
		MyHashKey mykey(&i, &dstAddr, &srcPort, &dstPort, &protocol, &tos);
		iter = myHashMap->find(mykey);
		if(iter!=myHashMap->end()){
			//access and print the key:
			//   cout << (iter->first).printkey() << "\n";
			//access the element (e.g., print out field 'info'): 
			//   cout << (iter->second)->info << "\n";
			found++;
		}
	}
	if(found != NUM_ELEMENTS){
		throw("ERROR: Not all inserted elements found! Aborting....\n");
	}

	//deleting elements while iterating over the hash table
	//NOTE 1: Elements are of POINTER TYPE. The memory used is 
	//        NOT automatically freed when deleting the element.
	//NOTE 2: Deletion of an hash table entry must NOT be done using
	//        the iterator itself -> memory exception. You must advance the
	//        iterator before deleting the entry!
	
	HashMap::iterator  iter_end = myHashMap->end();
	HashMap::iterator  iter_tmp;
	iter = myHashMap->begin();
	uint32_t deleted = 0;
	while(iter!=iter_end) {
		iter_tmp = iter;
		++iter;
		//we need to delete the element manualy (we allocated it with 'new'!
		delete iter_tmp->second;
		myHashMap->erase(iter_tmp);		
		deleted++;
	}
	if(deleted != NUM_ELEMENTS){
		cout << deleted << "\n";
		throw("ERROR: Not all inserted elements could be deleted! Aborting....\n");
	} else {
		cout << "Example SUCCESSFULLY completed!\n";
	} 
	delete myHashMap;
	}catch (char const * e){
		cout<< "Caught Exception: " << e << "\n";
	}
}
 * \endcode
 * Distributed under the Gnu Public License version 2 or the modified
 * BSD license (see file COPYING)
 *
 */

#include <arpa/inet.h>
#include "lookup3.h"
#include <ext/hash_map>

using namespace std;
using namespace __gnu_cxx;

#ifndef HASHMAP_H_
#define HASHMAP_H_


/* *************************************************************
 * Key type HashKeyGeneric: Arbitrary lengt key (slow)         *
 * *************************************************************/

/**
 * Holds a generic hash key. You can pass a pointer to the key and the key length. Use this class if
 * none of the other hash key classes are suitable. 
 */
class HashKeyGeneric {
	public:
	/**
	 * the key.
	 */
	char * key; 
	/**
	 * length of the key.
	 */
	uint8_t length;
	/**
	 * Constructor.
	 * \param buf pointer to the key
	 * \param len length of the key. Note that if you pass a pointer to a string (char array) it will not be 
	 * treated as a null-terminated string. Only the passed length is relevant.
	 */
	HashKeyGeneric(char* buf, uint8_t len);
	~HashKeyGeneric();

	size_t size() const;
        HashKeyGeneric(const HashKeyGeneric &b);
	std::string printkey() const;
};



/* *************************************************************
 * Key type HashKeyIPv4: IPv4 key                              *
 * *************************************************************/

/**
 * Hash Key for IPv4 addresses. The length is fixed to 4 bytes.
 */
class HashKeyIPv4 {
	private:
	/**
	 * the IPv4 address.
	 */
	public:
	char key[4]; 
	/**
	 * Constructor.
	 * \param ip the IPv4 address
	 */
	HashKeyIPv4(uint32_t * ip);
	~HashKeyIPv4();
	size_t size() const;
        HashKeyIPv4(const HashKeyIPv4 &b);
	std::string printkey() const;
};



/* *************************************************************
 * Key type HashKeyIPv4Pair: IPv4Pair key                      *
 * *************************************************************/

/**
 * Hash Key for IPv4 address pairs. The length is fixed to 8 bytes.
 */
class HashKeyIPv4Pair {
	private:
	/**
	 * the IPv4 address pair.
	 */
	public:
	char key[8]; 
	/**
	 * Constructor.
	 * \param ip the IPv4 address
	 */
	HashKeyIPv4Pair(uint32_t * ip1, uint32_t * ip2);
	~HashKeyIPv4Pair();
	size_t size() const;
        HashKeyIPv4Pair(const HashKeyIPv4Pair &b);
	std::string printkey() const;
};



/* *************************************************************
 * Key type HashKeyIPv6: IPv6 key                              *
 * *************************************************************/

/**
 * Hash Key for IPv6 addresses. The length is fixed to 16 bytes.
 */
class HashKeyIPv6 {
	private:
	/**
	 * the IPv6 address.
	 */
	public:
    char key [16]; 
	/**
	 * Constructor.
	 * \param ip the IPv6 address
	 */
	HashKeyIPv6(char * ip);
	~HashKeyIPv6();
	size_t size() const;
        HashKeyIPv6(const HashKeyIPv6 &b);
	std::string printkey() const;
};



/* *************************************************************
 * Key type HashKeyIPv4_3T: IPv4 Three-Tuple key               *
 * *************************************************************/

/**
 * Hash Key for 3-tuple [IP, potocol, port]. IP addresses are v4 (32 bits). The
 * size of the key amounts to 7 bytes.
 */
class HashKeyIPv4_3T {
	private:
	/**
	 * The 3-tuple
	 */
	public:
	char key [7]; 
	/**
	 * Constructor.
	 * \param IP IP address
	 * \param protocol protocol number (e.g. 6=tcp, 17=UDP)
	 * \param port port
	 */
	HashKeyIPv4_3T(uint32_t * IP, uint8_t * protocol, uint16_t * port);
	~HashKeyIPv4_3T();
	size_t size() const;
    HashKeyIPv4_3T(const HashKeyIPv4_3T &b);
	std::string printkey() const;
};



/* *************************************************************
 * Key type HashKeyIPv4_4T: IPv4 Four-Tuple key                *
 * *************************************************************/

/**
 * Hash Key for 4-tuple { localIP, remoteIP, potocol, direction }. IP addresses are v4 (32 bits). 
 * This key is useful for pairing unflows to biflows for non-TCP/UDP protocols missing port info.
 * The size of the key amounts to 10 bytes.
 */
class HashKeyIPv4_4T {
	private:
	/**
	 * The 4-tuple
	 */
	public:
	char key [10]; 
	/**
	 * Constructor.
	 * \param localIP   local IP address
	 * \param remoteIP  remoteIP address
	 * \param protocol  protocol number (e.g. 6=tcp, 17=UDP)
	 * \param direction flow direction information
	 */
	HashKeyIPv4_4T(uint32_t * localIP, uint32_t * remoteIP, uint8_t * protocol, uint8_t * direction);
	~HashKeyIPv4_4T();
	size_t size() const;
    HashKeyIPv4_4T(const HashKeyIPv4_4T &b);
	std::string printkey() const;
};




/* *************************************************************
 * Key type HashKeyIPv4_5T: IPv4 Five-Tuple key                *
 * *************************************************************/

/**
 * Hash Key for t-tuples [srcIP, dstIP, srcPort, dstPort, protocol]. IP addresses are v4 (32 bits). The
 * size of the key amounts to 13 bytes.
 */
class HashKeyIPv4_5T {
	private:
	/**
	 * The 5-tuple
	 */
	public:
	char key [13]; 
	/**
	 * Constructor.
	 * \param srcIP source IP address
	 * \param dstIP destination IP address
	 * \param srcPort source port
	 * \param dstPort destination port
	 * \param protocol protocol number (e.g. 6=tcp, 17=UDP)
	 */
	HashKeyIPv4_5T(uint32_t * srcIP,uint32_t * dstIP, uint16_t * srcPort,uint16_t * dstPort, uint8_t * protocol);
	~HashKeyIPv4_5T();
	size_t size() const;
    HashKeyIPv4_5T(const HashKeyIPv4_5T &b);
	std::string printkey() const;
};



/* *************************************************************
 * Key type HashKeyIPv4_6T: IPv4 Six-Tuple key                 *
 * *************************************************************/

/**
 * Hash Key for 6-tuples [srcIP, dstIP, srcPort, dstPort, protocol, TOS]. IP addresses are v4 (32 bits). 
 * Alternate fitting 6-tuple is 5-tuple plus direction, i.e. {localIP, remoteIP, localPort, remotePort,
 * protocol, direction }. This key is useful for hash map helping to pair uniflows to biflows.
 * The size of the key amounts to 14 bytes.
 */
class HashKeyIPv4_6T {
	private:
	/**
	 * The 6-tuple
	 */
	public:
	char key [14]; 
	/**
	 * Constructor.
	 * \param srcIP source IP address
	 * \param dstIP destination IP address
	 * \param srcPort source port
	 * \param dstPort destination port
	 * \param protocol protocol number (e.g. 6=tcp, 17=UDP)
	 * \param tos TOS field (Type Of Service)
	 */
	HashKeyIPv4_6T(uint32_t * srcIP,uint32_t * dstIP, uint16_t * srcPort,uint16_t * dstPort, uint8_t * protocol, uint8_t * tos);
	~HashKeyIPv4_6T();
	size_t size() const;
    HashKeyIPv4_6T(const HashKeyIPv4_6T &b);
	std::string printkey() const;
};



/* *************************************************************
 * Key type HashKeyIPv4_7T: IPv4 Seven-Tuple key               *
 * *************************************************************/

/**
 * Hash Key for 7-tuples [srcIP, dstIP, srcPort, dstPort, protocol, TOS, direction]. IP addresses are v4 (32 bits). The
 * size of the key amounts to 15 bytes.
 */
class HashKeyIPv4_7T {
	private:
	/**
	 * The 7-tuple
	 */
	public:
	char key [15];
	/**
	 * Constructor.
	 * \param srcIP source IP address
	 * \param dstIP destination IP address
	 * \param srcPort source port
	 * \param dstPort destination port
	 * \param protocol protocol number (e.g. 6=tcp, 17=UDP)
	 * \param tos TOS field (Type Of Service)
	 * \param dir Direction field
	 */
	HashKeyIPv4_7T(uint32_t * srcIP,uint32_t * dstIP, uint16_t * srcPort,uint16_t * dstPort, uint8_t * protocol, uint8_t * tos, uint8_t * dir);
	~HashKeyIPv4_7T();
	size_t size() const;
    HashKeyIPv4_7T(const HashKeyIPv4_7T &b);
	std::string printkey() const;
};



/* *************************************************************
 * HashFunction and Equality Operator definition               *
 * *************************************************************/

/**
 * Holds the implementation of the equals and hash operator for the different HashKeys.
 */
template <typename T> struct HashFunction {
	/**
	 * Hash function for HashKey class. The method hashlittle() is called on the key. See lookup3.h for details.
	 */
	size_t operator()(const T& key) const {
		return hashlittle(key.key, key.size(),0);
	}

	/**
	 * Equals operator for HashKey class. Two keys are equal if they have the same size and all bytes
	 * are equal.
	 */
	bool operator()(const T& key1, const T& key2) const {
		if(key1.size()!=key2.size()) return false;
		for(unsigned int i = 0; i<key1.size(); i++){
			if(key1.key[i]!=key2.key[i]) return false;
		}
		return true;
	}
}; 

#endif
