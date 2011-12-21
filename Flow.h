#ifndef FLOW_H_
#define FLOW_H_
/**
 *	\file Flow.h
 *
 *	\brief Implements a number of categories through an enum type and provides a counting
 *	facility for any combination of the categories. This is useful when an entity is
 *	assigned to more than one category at a time and, thus, intersections between the
 *	different category sets have to be tracked.
 *
 *
 * 	Copyright (c) 2010, Nicolas Bigler, Michael Fisler
 *
 * 	Authors: Nicolas Bigler (nbigler@hsr.ch)
 * 			 Michael Fisler (mfisler@hsr.ch)
 *
 *	Distributed under the Gnu Public License version 2 or the modified
 *	BSD license.
 */

#include <vector>
#include "libs/packet.h"
#include "libs/utils.h"

/**
 *	\class	Flow
 *	Contains a flow and the number of packets already matched
 */
class Flow {
private:
	cflow flow;
	int mached_packet_count;
	Flow();
public:
	Flow(cflow &fl) {
		flow = fl;
		mached_packet_count = 0;
	}

	/**
	 * Checks if the flow is incomplete
	 * @return TRUE if flow is incomplete, FALSE otherwise
	 */
	bool flow_incomplete() {
		return (mached_packet_count < static_cast<int>(flow.dPkts));
	}
	/**
	 * If the flow is not complete, it increases the mached_packet_count.
	 * @return	TRUE if flow is incomplete, FALSE otherwise
	 */
	bool can_increase_packet_count() {
		if (flow_incomplete()) {
			++mached_packet_count;
			return true;
		}
		return false;
	}

	cflow get_flow() {
		return flow;
	}
};

#endif /* FLOW_H_ */
