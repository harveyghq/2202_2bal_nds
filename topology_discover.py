from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib import hub
from ryu.topology.api import get_all_host, get_all_link, get_all_switch

class TopoDiscover(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(TopoDiscover, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topo_thread = hub.spawn(self._get_topology)

    def add_flow(self, datapath, priority, match, actions):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    def _get_topology(self):
        while True:
            self.logger.info('\n\n----------------------------')
            hosts = get_all_host(self)
            switches = get_all_switch(self)
            links = get_all_link(self)

            self.logger.info('hosts:')
            for hosts in hosts:
                self.logger.info(hosts.to_dict())

            self.logger.info('switches:')
            for switch in switches:
                self.logger.info(switch.to_dict())

            self.logger.info('links:')
            for link in links:
                self.logger.info(link.to_dict())
            
            self.logger.info('\n\n')
            hub.sleep(5)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) 
    def packet_in_handler(self, ev): 
        msg = ev.msg 
        dp = msg.datapath 
        ofp = dp.ofproto 
        parser = dp.ofproto_parser 
        
        # the identity of switch 
        dpid = dp.id 
        self.mac_to_port.setdefault(dpid,{}) 
        # the port that receive the packet 
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data) 
        eth_pkt = pkt.get_protocol(ethernet.ethernet) 
        # get the mac 
        dst = eth_pkt.dst 
        src = eth_pkt.src 


        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return
        
        # learn src2port mapping
        self.mac_to_port[dpid][src] = in_port
        
        # find out whether dst has a mapping
        if(self.mac_to_port[dpid].has_key(dst)):
            # use learned mapping
            dst_port = self.mac_to_port[dpid][dst]
            
            # add flow table
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            actions = [parser.OFPActionOutput(dst_port)]
            self.add_flow(dp, 1, match, actions)
            
            # send packet-out
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