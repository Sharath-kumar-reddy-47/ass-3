# firewall_monitor.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ether

class FirewallMonitor(app_manager.RyuApp):
    OFP_VERSION = ofproto_v1_3.OFP_VERSION

    def __init__(self, *args, **kwargs):
        super(FirewallMonitor, self).__init__(*args, **kwargs)
        self.firewall_rules = [
            {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.4"},
        ]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install firewall rules on the switches
        for rule in self.firewall_rules:
            match = parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ipv4_src=rule["src_ip"],
                ipv4_dst=rule["dst_ip"]
            )
            actions = []
            self.add_flow(datapath, 1, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Monitor packets coming from host H3 on switch S1
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        src_ip = msg.match['ipv4_src']
        if src_ip == "10.0.0.3" and datapath.id == 1:
            self.logger.info("Packet from H3 on S1: in_port=%d, src_ip=%s", in_port, src_ip)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

if __name__ == '__main__':
    from ryu import cfg
    cfg.CONF(args=[], default_config_files=['firewall_monitor.ini'])
    app_manager.run_app('firewall_monitor')
