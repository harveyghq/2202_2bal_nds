from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_host, get_link, get_switch

import networkx as nx
import copy
import time
import threading

GET_TOPOLOGY_INTERVAL = 2
SEND_ECHO_REQUEST_INTERVAL = .05
GET_DELAY_INTERVAL = 2
CALC_DELAY_INTERVAL = 3

class NetworkAwareness(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)
        self.switch_info = {}  # dpid: datapath
        self.link_info = {}  # (s1, s2): s1.port   (s1, host_ip): s1.port
        self.port_link = {} # (s1, port): (s1, s2)
        self.port_info = {}  # dpid: (ports linked hosts)
        self.switches = None

        self.topo_map_sem = threading.Semaphore()
        self.topo_map = nx.Graph()
        self.topo_thread = hub.spawn(self._get_topology)
        self.echo_thread = hub.spawn(self._send_echo_request)
        self.calc_thread = hub.spawn(self.calc_delay)
        
        self.echo_send_timestamp = {} # dpid: send_timestamp
        self.echo_delay = {} # dpid: echo_delay
        self.lldp_delay = {} # (s1, s2): lldp_delay from s1 to s2
        self.delay = {} # (src_dpid, dst_dpid): time
        
        self.weight = 'delay'

    def add_flow(self, datapath, priority, match, actions):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)

    def delete_flow(self, datapath, out_port, match):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        mod = parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                out_port=out_port, out_group=ofp.OFPG_ANY,
                                match=match)
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

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        dpid = dp.id

        if ev.state == MAIN_DISPATCHER:
            self.switch_info[dpid] = dp

        if ev.state == DEAD_DISPATCHER:
            del self.switch_info[dpid]

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if msg.reason in [ofproto.OFPPR_ADD, ofproto.OFPPR_MODIFY]:
            datapath.ports[msg.desc.port_no] = msg.desc
        elif msg.reason == ofproto.OFPPR_DELETE:
            datapath.ports.pop(msg.desc.port_no, None)
        else:
            return

        if msg.desc.state == ofproto.OFPPS_LINK_DOWN:
            self.logger.info("%s.%s: MODIFY(LINK_DOWN)", datapath.id, msg.desc.port_no)
            if (datapath.id, msg.desc.port_no) in self.port_link:
                switch_link = self.port_link[(datapath.id, msg.desc.port_no)] # (s1, s2)
                if switch_link in self.lldp_delay:
                    self.logger.info("lldp_delay (%s) deleted", switch_link)
                    del self.lldp_delay[switch_link]
        elif msg.desc.state == ofproto.OFPPS_LIVE:
            self.logger.info("%s.%s: MODIFY(LIVE)", datapath.id, msg.desc.port_no)
        
        match = parser.OFPMatch()
        self.delete_flow(datapath, ofproto.OFPP_ANY, match)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    
    @set_ev_cls(ofp_event.EventOFPEchoReply,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        if(self.echo_send_timestamp.has_key(dp.id)):
            self.echo_delay[dp.id] = time.time() - self.echo_send_timestamp[dp.id]
            # self.logger.info("received s%s echo reply packet: %sms", dp.id, (time.time() - self.echo_send_timestamp[dp.id]) * 1000)        
            del self.echo_send_timestamp[dp.id]
    
    def _send_echo_request(self):
        while True:
            for dp in self.switch_info.values():
                echo_req = dp.ofproto_parser.OFPEchoRequest(dp)
                self.echo_send_timestamp[dp.id] = time.time()
                dp.send_msg(echo_req)
                # self.logger.info("sent echo request packet to s%s", dp.id)        
                hub.sleep(SEND_ECHO_REQUEST_INTERVAL) # request interval
            hub.sleep(3) # total loop

    def _get_topology(self):
        _hosts, _switches, _links = None, None, None
        while True:
            hosts = get_host(self)
            switches = get_switch(self)
            links = get_link(self)

            # update topo_map when topology change
            if [str(x) for x in hosts] == _hosts and [str(x) for x in switches] == _switches and [str(x) for x in links] == _links:
                continue
            _hosts, _switches, _links = [str(x) for x in hosts], [str(x) for x in switches], [str(x) for x in links]
            
            self.topo_map_sem.acquire()
            self.logger.info("_get_topology lock acquired")
            self.topo_map = nx.Graph() # clear old topo map

            for switch in switches:
                self.port_info.setdefault(switch.dp.id, set())
                # record all ports
                for port in switch.ports:
                    self.port_info[switch.dp.id].add(port.port_no)

            for host in hosts:
                # take one ipv4 address as host id
                if host.ipv4:
                    self.link_info[(host.port.dpid, host.ipv4[0])] = host.port.port_no
                    self.topo_map.add_edge(host.ipv4[0], host.port.dpid, hop=1, delay=0, is_host=True)
            for link in links:
                # delete ports linked switches
                self.port_info[link.src.dpid].discard(link.src.port_no)
                self.port_info[link.dst.dpid].discard(link.dst.port_no)

                # s1 -> s2: s1.port, s2 -> s1: s2.port
                self.port_link[(link.src.dpid,link.src.port_no)] = (link.src.dpid, link.dst.dpid)
                self.port_link[(link.dst.dpid,link.dst.port_no)] = (link.dst.dpid, link.src.dpid)

                self.link_info[(link.src.dpid, link.dst.dpid)] = link.src.port_no
                self.link_info[(link.dst.dpid, link.src.dpid)] = link.dst.port_no

                try:
                    delay  = self.lldp_delay[(link.src.dpid, link.dst.dpid)] + self.lldp_delay[(link.dst.dpid, link.src.dpid)]
                    delay -= self.echo_delay[link.src.dpid] - self.echo_delay[link.dst.dpid]
                    delay /= 2
                    if(delay < 0):
                        delay = 0

                    self.topo_map.add_edge(link.src.dpid, link.dst.dpid, hop=1, delay=delay, is_host=False)

                except:
                    self.logger.warn("calc s%s<->s%s delay fail(%s %s %s %s)", link.src.dpid, link.dst.dpid, self.lldp_delay.has_key((link.src.dpid, link.dst.dpid)), self.lldp_delay.has_key((link.dst.dpid, link.src.dpid)) \
                        , self.echo_delay.has_key(link.src.dpid), self.echo_delay.has_key(link.dst.dpid))


            if self.weight == 'hop':
                self.show_topo_map()
            self.logger.info("_get_topology lock released")
            self.topo_map_sem.release()
            hub.sleep(GET_TOPOLOGY_INTERVAL)
    
    def calc_delay(self):
        while True:
            self.topo_map_sem.acquire()
            self.logger.info("calc_delay lock acquired")
            self.delay = {}
            for src_dpid, dst_dpid in self.port_link.values():
                try:
                    delay  = self.lldp_delay[(src_dpid, dst_dpid)] + self.lldp_delay[(dst_dpid, src_dpid)]
                    delay -= self.echo_delay[src_dpid] - self.echo_delay[dst_dpid]
                    delay /= 2
                    if(delay < 0):
                        delay = 0

                    self.delay[(src_dpid, dst_dpid)] = delay
                    self.delay[(dst_dpid, src_dpid)] = delay

                    self.topo_map.add_edge(src_dpid, dst_dpid, hop=1, delay=delay, is_host=False)

                except:
                    pass
            for key, value in sorted(self.delay.items()):
                self.logger.info("%s %sms", key, str(value*1000)[:4])
            self.logger.info("calc_delay lock released")
            self.topo_map_sem.release()
            hub.sleep(CALC_DELAY_INTERVAL)

    def shortest_path(self, src, dst, weight='hop'):
        try:
            paths = list(nx.shortest_simple_paths(self.topo_map, src, dst, weight=weight))
            return paths[0]
        except:
            self.logger.info('host not find/no path')

    def show_topo_map(self):
        self.logger.info('topo map:')
        self.logger.info('{:^10s}  ->  {:^10s}'.format('node', 'node'))
        for src, dst in self.topo_map.edges:
            self.logger.info('{:^10s}      {:^10s}'.format(str(src), str(dst)))
        self.logger.info('\n')

