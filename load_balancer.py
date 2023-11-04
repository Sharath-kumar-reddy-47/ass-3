from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.ofproto.ofproto_v1_3_parser import OFPActionSetField, OFPMatch

class SimpleLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleLoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.server_ips = ["10.0.0.4", "10.0.0.5"]  # IPs of H4 and H5
        self.virtual_ip = "10.0.0.42"
        self.server_count = len(self.server_ips)
        self.next_server_index = 0  # Index for round-robin load balancing

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
        actions = [OFPActionSetField(eth_dst="ff:ff:ff:ff:ff:ff"),
                   ofproto.OFPP_FLOOD]  # Use ofproto.OFPP_FLOOD here
        match = OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_op=arp.ARP_REQUEST, arp_tpa=target_ip)
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
        arp_pkt = pkt.get_protocols(arp.arp)[0]

        if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.virtual_ip:
            # If ARP request for virtual IP is received, reply with the MAC of switch port
            self.reply_to_arp(datapath, eth, arp_pkt, in_port)

    def reply_to_arp(self, datapath, eth, arp_pkt, in_port):
        ofproto = datapath.ofproto

        dst_mac = eth.src
        src_mac = '00:00:00:00:00:0' + str(in_port)  # Create a unique MAC address for each port
        target_ip = arp_pkt.src_ip
        sender_ip = arp_pkt.dst_ip

        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                                 dst=dst_mac, src=src_mac))
        arp_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                     src_mac=src_mac, src_ip=sender_ip,
                                     dst_mac=dst_mac, dst_ip=target_ip))

        data = arp_reply.data

        actions = [parser.OFPActionOutput(in_port, ofproto.OFPCML_NO_BUFFER)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

    def handle_ipv4_packet(self, datapath, in_port, pkt):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt.dst == self.virtual_ip:
            # If the destination IP is the virtual IP, balance the traffic
            out_port = self.get_next_server_port(datapath)
            actions = [OFPActionSetField(eth_dst=self.server_mac(out_port)),
                       ofproto.OFPP_TABLE]  # Use OFP_ACTION_OUTPUT instead
            match = OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=self.virtual_ip)
            self.add_flow(datapath, 1, match, actions)

    def get_next_server_port(self, datapath):
        # Round-robin load balancing to distribute traffic to servers
        out_port = (self.next_server_index % self.server_count) + 1
        self.next_server_index = (self.next_server_index + 1) % self.server_count
        return out_port

    def server_mac(self, port):
        return '00:00:00:00:00:%02x' % port

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
