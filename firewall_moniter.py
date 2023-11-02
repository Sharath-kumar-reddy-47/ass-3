from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.ofproto.ofproto_v1_3_parser import OFPActionSetField, OFPMatch
from ryu.lib import mac

class FirewallMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FirewallMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.firewall_rules = [
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.4"},  # H1 to H4
            {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.5"},  # H3 to H5
            {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"},  # H2 to H3
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},  # H1 to H2
        ]
        self.packet_count = 0  # Packet count from H3 on S1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install firewall rules
        for rule in self.firewall_rules:
            match = OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                             ipv4_src=rule["src_ip"],
                             ipv4_dst=rule["dst_ip"])
            actions = []
            self.add_flow(datapath, 1, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)

            # Count packets from H3 on switch S1
            if datapath.id == 1 and ip.src == "10.0.0.3":
                self.packet_count += 1
                self.logger.info("Packet count from H3 on S1: %d", self.packet_count)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
