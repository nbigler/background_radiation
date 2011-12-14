#ifndef FLOW_H_
#define FLOW_H_

#include <vector>
#include "libs/packet.h"
#include "libs/utils.h"

class Flow {
	private:
		cflow flow;
		std::vector<packet> packets;
		Flow();
	public:
		Flow(cflow &fl) {
			flow = fl;
		}

		bool flow_incomplete() {
			return (packets.size() < static_cast<int>(flow.dPkts));
		}

		bool add(const packet & pck) {
			if(flow_incomplete()){
				packets.push_back(pck);
				return true;
			}else{
//				std::cerr << "Number of packets must not exceed number of packets in flow" << std::endl;
//				util::print_packet(pck);
			}
			return false;
		}

		cflow get_flow() {
			return flow;
		}

		const vector<packet> get_packets() {
			return packets;
		}
};


#endif /* FLOW_H_ */
