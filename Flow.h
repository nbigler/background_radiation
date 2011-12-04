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

		bool flow_complete() {
			return packets.size() == static_cast<int>(flow.dPkts);
		}

		void add(const packet & pck) {
			bool packet_belongs_to_flow = (flow.startMs - 1 <= pck.timestamp/1000) && (pck.timestamp/1000 <= (flow.startMs + flow.durationMs) + 1);

			if(packet_belongs_to_flow){
				if(!flow_complete()){
					packets.push_back(pck);
				}else{
					std::cerr << "Number of packets must not exceed number of packets in flow" << std::endl;
					util::print_packet(pck);
				}
			}
		}

		cflow get_flow() {
			return flow;
		}

		const vector<packet> get_packets() {
			return packets;
		}

};


#endif /* FLOW_H_ */
