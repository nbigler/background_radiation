#ifndef FLOW_H_
#define FLOW_H_

#include <vector>
#include "libs/packet.h"

class flow {
	private:
		cflow flow;
		std::vector<packet> packets;
		flow();
	public:
		flow(cflow &flow) {
			this.flow == flow;
		}

		flow(cflow &flow, std::vector<packet> &packets) {
			this->flow = flow;
			if(packets.size() == static_cast<int>(flow.dPkts)) {
				this->packets = packets;
			} else {
				std::cerr << "Packetsize not equal to packets in flow" << std::endl;
			}
		}

		void add(packet &pck) {
			packets.push_back(pck);
		}
};


#endif /* FLOW_H_ */
