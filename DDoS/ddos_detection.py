from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from collections import defaultdict
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
import time

class DDoSDetectionSensitive(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetectionSensitive, self).__init__(*args, **kwargs)
        self.packet_in_counter = defaultdict(lambda: defaultdict(int))  # Counter untuk setiap IP sumber
        self.start_time = time.time()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("Switch connected: %s", ev.msg.datapath.id)
        self.install_default_flow(ev.msg.datapath)

    def install_default_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        current_time = time.time()
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if ip:  # Hanya hitung jika paket memiliki header IPv4
            src_ip = ip.src
            self.packet_in_counter[dpid][src_ip] += 1

        # Log setiap detik
        if current_time - self.start_time >= 1:
            for dpid, src_counts in self.packet_in_counter.items():
                for src_ip, count in src_counts.items():
                    if count > 1:  # Threshold untuk setiap IP sumber
                        self.logger.warning(
                            "Potensi serangan DDoS dari IP %s di switch %s: %d Packet-In per detik",
                            src_ip, dpid, count)
            # Reset counter dan waktu
            self.packet_in_counter = defaultdict(lambda: defaultdict(int))
            self.start_time = current_time
