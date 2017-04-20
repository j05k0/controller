import logging
import struct
import socket

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,HANDSHAKE_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu import utils
from ryu.topology import event
from ryu.app import rest_topology



class MySwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MySwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_mac = {}
        self.l2ovs_dpid = [5,6,7]
        self.dp_lsit = []
        self.ovs_mac_list = ['00:00:00:00:00:21','00:00:00:00:00:22','00:00:00:00:00:23',
            '00:00:00:00:00:24','00:00:00:00:00:25','00:00:00:00:00:26','00:00:00:00:00:27']


    def add_flow1(self, datapath, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=30000,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)


    def add_flow2(self, datapath, l3dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            dl_type=0x0800,nw_dst=struct.unpack('!I', socket.inet_aton(l3dst))[0])

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=30001,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)


    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
            priority=30000)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        if datapath not in self.dp_lsit:
            self.dp_lsit.append(datapath)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        if pkt.get_protocol(ipv4.ipv4):
            v4 = pkt.get_protocol(ipv4.ipv4)
            l3dst = v4.dst
            l3src = v4.src
            if src not in self.ovs_mac_list:
                self.ip_mac[l3src] = src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if eth.ethertype != 0x86dd and dpid != 1:

            self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)
            self.mac_to_port[dpid][src] = msg.in_port

            if dpid not in self.l2ovs_dpid and eth.ethertype == 0x0806 and dst == 'ff:ff:ff:ff:ff:ff':
                out_port = ofproto.OFPP_LOCAL
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                    actions=actions)
                datapath.send_msg(out)
            else:
                if dpid in self.l2ovs_dpid and src in self.ip_mac.values() and eth.ethertype == 0x0806:
                    match1 = datapath.ofproto_parser.OFPMatch(dl_dst=haddr_to_bin(src))
                    for k in self.ip_mac:
                        if self.ip_mac[k] == src:
                            break
                    match2 = datapath.ofproto_parser.OFPMatch(dl_type=0x0800,
                        nw_dst=struct.unpack('!I', socket.inet_aton(k))[0])

                    for i in self.mac_to_port:
                        if self.mac_to_port[i].has_key(src):
                            self.mac_to_port[i].pop(src)
                            for j in self.dp_lsit:
                                if i == j.id:
                                    self.del_flow(j,match1)
                                    self.del_flow(j,match2)

                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD

                if pkt.get_protocol(ipv4.ipv4) and self.ip_mac.has_key(l3dst) and self.ip_mac[l3dst] != dst:
                    out_port = self.mac_to_port[dpid][self.ip_mac[l3dst]]
                    actions = [datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(self.ip_mac[l3dst])),
                        datapath.ofproto_parser.OFPActionOutput(out_port)]
                    self.add_flow2(datapath, l3dst, actions)
                else:
                    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                # install a flow to avoid packet_in next time
                    if out_port != ofproto.OFPP_FLOOD:
                        self.add_flow1(datapath,  dst, actions)

                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                    actions=actions)
                datapath.send_msg(out)
