# ryu-manager shortest_forward.py --observe-links
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4
from ryu.controller import ofp_event
from ryu.lib.packet import ether_types
from ryu.topology.switches import LLDPPacket
from network_awareness import NetworkAwareness

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__
class ShortestForward(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'network_awareness': NetworkAwareness
    }

    def __init__(self, *args, **kwargs):
        super(ShortestForward, self).__init__(*args, **kwargs)
        self.network_awareness = kwargs['network_awareness']
        self.weight = 'delay'
        self.mac_to_port = {}
        self.mac_ip_inport = {}
        self.sw = {}

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        dpid = dp.id
        in_port = msg.match['in_port']

        self.mac_to_port.setdefault(dpid, {})
        self.mac_ip_inport.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        pkt_type = eth_pkt.ethertype

        # layer 2 self-learning
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src

        if pkt_type == ether_types.ETH_TYPE_LLDP:
            self.handle_lldp(msg)
            return

        if isinstance(arp_pkt, arp.arp):
            self.handle_arp(msg, in_port, dst_mac, src_mac, pkt, pkt_type)

        if isinstance(ipv4_pkt, ipv4.ipv4):
            self.handle_ipv4(msg, ipv4_pkt.src, ipv4_pkt.dst, pkt_type)
    
    def handle_lldp(self, msg):
        dpid = msg.datapath.id
        try:
            src_dpid, src_port = LLDPPacket.lldp_parse(msg.data)
            if self.network_awareness.switches is None:
                self.network_awareness.switches = lookup_service_brick('switches')
            for port in self.network_awareness.switches.ports.keys():
                if src_dpid == port.dpid and src_port== port.port_no:
                    self.network_awareness.lldp_delay[(src_dpid, dpid)] = self.network_awareness.switches.ports[port].delay
                    # self.logger.info("lldp_delay[(%s, %s)] = %sms", src_dpid, dpid, self.network_awareness.switches.ports[port].delay * 1000)
        except:
            return

    def handle_arp(self, msg, in_port, dst, src, pkt, pkt_type):
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id
        in_port = msg.match['in_port']
        src_ip = pkt.get_protocol(arp.arp).src_ip
        dst_ip = pkt.get_protocol(arp.arp).dst_ip
        if(self.mac_ip_inport[dpid].has_key(src) and self.mac_ip_inport[dpid][src].has_key(dst_ip) and self.mac_ip_inport[dpid][src][dst_ip] != in_port):
            # drop it
            # self.logger.info('%s: ARP packet query %s from host %s port %s(ori: %s) has dropped because of loop.', dpid, dst_ip, src, in_port, self.mac_ip_inport[dpid][src][dst_ip])
            return
        # add record and flood it
        if(not self.mac_ip_inport[dpid].has_key(src)):
            self.mac_ip_inport[dpid][src] = {}
        self.mac_ip_inport[dpid][src][dst_ip] = in_port
        # self.logger.info('%s: ARP packet query %s from host %s port %s first flood.', dpid, dst_ip, src, in_port)

        # learn src2port mapping
        self.mac_to_port[dpid][src] = in_port
        
        # find out whether dst has a mapping
        if(self.mac_to_port[dpid].has_key(dst)):
            # use learned mapping
            dst_port = self.mac_to_port[dpid][dst]
            
            # add flow table
            match = parser.OFPMatch(in_port=in_port, eth_type=pkt_type, eth_dst=dst)
            actions = [parser.OFPActionOutput(dst_port)]
            self.add_flow(dp, 1, match, actions, 10, 30)

            # send packet-out
            actions = [parser.OFPActionOutput(dst_port)]
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=msg.match['in_port'],actions=actions, data=msg.data)
            dp.send_msg(out)

            # self.logger.info('%s: packet: %s to %s from port %s to port %s', dpid, src, dst, in_port, dst_port)
        else:
            # have to flood
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id, 
                in_port=msg.match['in_port'],actions=actions, data=msg.data)
            dp.send_msg(out)
        
            # self.logger.info('%s: packet: %s to %s from port %s to port ? (flooded)', dpid, src, dst, in_port)


    def handle_ipv4(self, msg, src_ip, dst_ip, pkt_type):
        parser = msg.datapath.ofproto_parser

        dpid_path = self.network_awareness.shortest_path(src_ip, dst_ip, weight=self.weight)
        if not dpid_path:
            return


        if self.network_awareness.path is None:
            self.network_awareness.path = []
        self.network_awareness.path.append(dpid_path)
        # get port path:  h1 -> in_port, s1, out_port -> h2
        port_path = []
        for i in range(1, len(dpid_path) - 1):
            in_port = self.network_awareness.link_info[(dpid_path[i], dpid_path[i - 1])]
            out_port = self.network_awareness.link_info[(dpid_path[i], dpid_path[i + 1])]
            port_path.append((in_port, dpid_path[i], out_port))
        self.show_path(src_ip, dst_ip, port_path)
        # calc path delay


        # send flow mod
        for node in port_path:
            in_port, dpid, out_port = node
            self.send_flow_mod(parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port)
            self.send_flow_mod(parser, dpid, pkt_type, dst_ip, src_ip, out_port, in_port)

        # send packet_out
        _, dpid, out_port = port_path[-1]
        dp = self.network_awareness.switch_info[dpid]
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    def send_flow_mod(self, parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port):
        dp = self.network_awareness.switch_info[dpid]
        match = parser.OFPMatch(
            in_port=in_port, eth_type=pkt_type, ipv4_src=src_ip, ipv4_dst=dst_ip)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(dp, 1, match, actions, 15, 30)

    def show_path(self, src, dst, port_path):
        self.logger.info('path: {} -> {}'.format(src, dst))
        path = src + ' -> '
        for node in port_path:
            path += '{}:s{}:{}'.format(*node) + ' -> '
        path += dst
        self.logger.info(path)