#ifndef FLOW_H_
#define FLOW_H_

#include <vector>
#include "libs/packet.h"

class Flow {
	private:
		cflow flow;
		std::vector<packet> packets;
		Flow();
	public:
		Flow(cflow &fl) {
			flow = fl;
		}

		void add(const packet &pck) {
			if(packets.size() <= static_cast<int>(flow.dPkts)) {
				packets.push_back(pck);
			} else {
				std::cerr << "Number of packets must not exceed number of packets in flow" << std::endl;
			}
		}

		cflow get_flow() {
			return flow;
		}

		const vector<packet> get_packets() {
			return packets;
		}

//		void get_packet_count() {
//			return packets.size();
//		}
};


#endif /* FLOW_H_ */
