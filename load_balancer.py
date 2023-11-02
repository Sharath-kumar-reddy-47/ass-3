from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp

class SimpleLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleLoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.server_ips = ["10.0.0.4", "10.0.0.5"]
        self.current_server = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Add ARP handling
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # Handle ARP request
            self.handle_arp_request(datapath, pkt, in_port)
            return

        # Implement round-robin load balancing for non-ARP packets
        # Choose the next server for the current flow
        self.current_server = (self.current_server + 1) % len(self.server_ips)
        server_ip = self.server_ips[self.current_server]

        # Build the flow rule to forward traffic to the selected server
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=server_ip)
        actions = [parser.OFPActionOutput(2)]  # Assuming the server is connected to port 2
        self.add_flow(datapath, 1, match, actions)

        # Apply the selected flow rule
        self.apply_selected_flow(datapath, in_port, msg.data)

    def handle_arp_request(self, datapath, pkt, in_port):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Generate ARP reply
            src_mac = self.mac_to_port[datapath.id].get(in_port)
            if src_mac is not None:
                src_ip = arp_pkt.dst_ip
                dst_ip = arp_pkt.src_ip
                eth_dst = pkt.get_protocol(ethernet.ethernet).src
                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                                         dst=eth_dst, src=src_mac))
                arp_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                            src_mac=src_mac, src_ip=dst_ip,
                                            dst_mac=arp_pkt.src_mac, dst_ip=src_ip))
                arp_reply.serialize()
                actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                    data=arp_reply.data)
                datapath.send_msg(out)

    def apply_selected_flow(self, datapath, in_port, data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(2)]  # Output to the selected server port
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

if __name__ == '__main__':
    from ryu.cmd import manager
    manager.main(['--ofp-listen-host', '127.0.0.1', 'SimpleLoadBalancer'])
