from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from collections import defaultdict
import time

class DDoSDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetection, self).__init__(*args, **kwargs)
        self.packet_in_counter = defaultdict(int)
        self.start_time = time.time()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Menghitung jumlah packet-in per detik
        current_time = time.time()
        dpid = ev.msg.datapath.id
        self.packet_in_counter[dpid] += 1
        
        # Periksa setiap 1 detik
        if current_time - self.start_time >= 1:
            for dpid, count in self.packet_in_counter.items():
                if count > 0:  # Threshold (sesuaikan dengan kebutuhan)
                    self.logger.warning(
                        "Potensi serangan DDoS terdeteksi di switch %s: %d Packet-In per detik",
                        dpid, count)
            # Reset counter dan waktu
            self.packet_in_counter = defaultdict(int)
            self.start_time = current_time
