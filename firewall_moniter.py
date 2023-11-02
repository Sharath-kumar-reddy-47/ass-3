from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

class FirewallMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FirewallMonitor, self).__init__(*args, **kwargs)
        self.firewall_rules = [
            {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.4"}
        ]
        self.packet_count = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install firewall rules on each switch
        for rule in self.firewall_rules:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=rule["src_ip"],
                ipv4_dst=rule["dst_ip"]
            )
            actions = []  # Drop the packet
            self.add_flow(datapath, 1, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(packet.ipv4.ipv4)
            if ip_pkt.src == "10.0.0.3":
                # Count packets from host H3 on switch S1
                self.packet_count += 1

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)
