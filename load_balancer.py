from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4  # Import the ipv4 module

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.server_ips = ["10.0.0.4", "10.0.0.5"]  # IPs of H4 and H5
        self.virtual_ip = "10.0.0.42"
        self.server_count = len(self.server_ips)
        self.next_server_index = 0 

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Handle ARP requests for the virtual IP address
        self.handle_arp_request(datapath, self.virtual_ip)

    def handle_arp_request(self, datapath, target_ip):
        ofproto = datapath.ofproto

        # Handle ARP requests for the virtual IP address
        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=target_ip)
        self.add_flow(datapath, 1, match, actions)

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
            # Handle ARP packets
            self.handle_arp_packet(datapath, in_port, pkt)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            # Handle IPv4 packets
            self.handle_ipv4_packet(datapath, in_port, pkt)

    def handle_arp_packet(self, datapath, in_port, pkt):
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp = pkt.get_protocols(arp.arp)[0]

        if arp.opcode == arp.ARP_REQUEST and arp.dst_ip == self.virtual_ip:
            # If ARP request for virtual IP is received, reply with the MAC of switch port
            self.reply_to_arp(datapath, eth, arp, in_port)

    def reply_to_arp(self, datapath, eth, arp, in_port):
        ofproto = datapath.ofproto

        dst_mac = eth.src
        src_mac = '00:00:00:00:00:0' + str(in_port)  # Create a unique MAC address for each port
        target_ip = arp.src_ip
        sender_ip = arp.dst_ip

        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                                 dst=dst_mac, src=src_mac))
        arp_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                     src_mac=src_mac, src_ip=sender_ip,
                                     dst_mac=dst_mac, dst_ip=target_ip))

        data = arp_reply.data

        actions = [datapath.ofproto_parser.OFPActionOutput(in_port, ofproto.OFPCML_NO_BUFFER)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

    def handle_ipv4_packet(self, datapath, in_port, pkt):
        ip = pkt.get_protocols(ipv4.ipv4)[0]
        dst_ip = ip.dst

        if dst_ip == self.virtual_ip:
            # If the destination IP is the virtual IP, balance the traffic
            out_port = self.get_next_server_port(datapath)
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=self.virtual_ip)
            self.add_flow(datapath, 1, match, actions)

    def get_next_server_port(self, datapath):
        # Round-robin load balancing to distribute traffic to servers
        out_port = (self.next_server_index % self.server_count) + 1
        self.next_server_index = (self.next_server_index + 1) % self.server_count
        return out_port

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
