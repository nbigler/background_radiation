#ifndef FLOW_H_
#define FLOW_H_

#include <vector>
#include "libs/packet.h"
#include "libs/utils.h"

class Flow {
	private:
		cflow flow;
		//std::vector<packet> packets;
		int packetcount;
		Flow();
	public:
		Flow(cflow &fl) {
			flow = fl;
		}

		bool flow_complete() {
			return packetcount == static_cast<int>(flow.dPkts);
		}

		bool add(const packet & pck) {
			bool packet_belongs_to_flow = (flow.startMs - 1 <= pck.timestamp/1000) && (pck.timestamp/1000 <= (flow.startMs + flow.durationMs) + 1);

			if(packet_belongs_to_flow){
				if(!flow_complete()){
					++packetcount;
					return true;
					//packets.push_back(pck);
				}else{
					std::cerr << "Number of packets must not exceed number of packets in flow" << std::endl;
					util::print_packet(pck);
				}
			}
			return false;
		}

		cflow get_flow() {
			return flow;
		}

		/*const vector<packet> get_packets() {
			return packets;
		}*/

};


#endif /* FLOW_H_ */
