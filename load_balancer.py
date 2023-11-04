from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet.ether_types import ether_types  # Corrected import

class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    VIRTUAL_IP = '10.0.0.42'
    SERVERS = [
        {'ip': '10.0.0.4', 'mac': '00:00:00:00:00:04', 'port': 4},
        {'ip': '10.0.0.5', 'mac': '00:00:00:00:00:05', 'port': 5}
    ]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.server_index = 0  # Round-robin server selection index

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Ignore LLDP packets

        dst_mac = eth.dst
        src_mac = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn source MAC address to avoid flooding next time
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac == self.VIRTUAL_IP:
            # If the destination IP is the virtual IP, perform load balancing
            self.load_balance(datapath, in_port, pkt)
            return

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
        self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def load_balance(self, datapath, in_port, pkt):
        server = self.SERVERS[self.server_index]
        self.server_index = (self.server_index + 1) % len(self.SERVERS)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionSetField(ipv4_dst=server['ip']),
                   parser.OFPActionSetField(eth_dst=server['mac']),
                   parser.OFPActionOutput(server['port'])]

        data = None
        if pkt.get_protocol(ipv4.ipv4):
            data = pkt.protocols[-1]

        out = parser.OFPPacketOut(datapath=datapath, in_port=in_port,
                                  actions=actions, data=data)
        datapath.send_msg(out)

        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=self.VIRTUAL_IP)
        self.add_flow(datapath, 1, match, actions)

        self.logger.info("Load balanced packet to server %s (%s) from %s on port %d",
                         server['ip'], server['mac'], pkt.get_protocol(ipv4.ipv4).src, in_port)
