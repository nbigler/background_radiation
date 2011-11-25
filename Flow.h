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

		void add(const packet & pck) {
			bool packet_belongs_to_flow = (pck.ipPayload.timestamp <= flow.startMs - 1) && (pck.ipPayload.timestamp <= (flow.startMs + flow.durationMs) - 1);
			bool flow_not_complete = packets.size() < static_cast<int>(flow.dPkts);

			if(packet_belongs_to_flow){
				if(flow_not_complete){
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

//		void get_packet_count() {
//			return packets.size();
//		}
};


#endif /* FLOW_H_ */
