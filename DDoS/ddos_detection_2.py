from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


###################


from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
###############
from operator import attrgetter
from datetime import datetime
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
##################


from ryu.base.app_manager import RyuApp
from ryu.controller.ofp_event import EventOFPSwitchFeatures
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
from ryu.ofproto.ofproto_v1_3 import OFP_VERSION
from ryu.lib.mac import haddr_to_bin
###################

# Fungsi pengiriman email
from collections import defaultdict
import smtplib
from email.mime.text import MIMEText



class DDoSDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetection, self).__init__(*args, **kwargs)
        #self.packet_counts = defaultdict(int)  # Penghitung paket per IP
        self.threshold = 50  # Ambang batas jumlah paket untuk DDoS
        self.email_sent = set()  # Mencatat IP yang sudah dikirimi email
        
        # Konfigurasi email
        self.from_email = "socialme.black@gmail.com"  # Ganti dengan email Anda
        self.password = "jyzemtausobocqjy"  # Ganti dengan password email Anda
        self.to_email = "zanimumu@gmail.com"  # Ganti dengan email penerima
        
        self.mac_to_port = {}
        self.mac_ip_to_dp = {}            #dict 
        self.datapaths = {}
        self.match_miss_flow_entry = ""
        self.actions_miss_flow_entry = ""
        self.ddos_oocurs=False
        self.src_of_DDOS =0     #src mac
        self.monitor_thread = hub.spawn(self._monitor)
        
    def _monitor(self):
        while True:
            hub.sleep(10) 

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Menambahkan flow saat switch pertama kali terhubung ke controller."""
        self.logger.info("Switch connected: %s", ev.msg.datapath.id)
        # Kirim email notifikasi saat switch baru terhubung
        # switch_id = ev.msg.datapath.id
        # subject = "Notifikasi SDN - Switch Baru Terhubung"
        # message = f"Switch dengan ID {switch_id} telah terhubung ke controller."        
        # send_email(subject, message, self.to_email, self.from_email, self.password)
        # self.logger.info(f"Email notifikasi dikirim untuk switch ID: {switch_id}")
        
        #kirim email jika ada serangan
        #self.install_default_flow(ev.msg.datapath)
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        self.match_miss_flow_entry = match
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.actions_miss_flow_entry = actions                                          
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
            
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):                             
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src
        if(self.src_of_DDOS != src) and self.ddos_oocurs:
            self.ddos_oocurs = 0
            self.mac_ip_to_dp ={}
            return          #during DDOS

        dpid = datapath.id
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        src_ip = ip_pkt.src
        dest_ip = ip_pkt.dst
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_ip_to_dp.setdefault(src, {})           
        
        #print("msg from dpid ",dpid," src mac is ",src," dst mac is ",dst)
        print("msg ICMP from IP ",icmp_pkt," src IP is ",src_ip," dst IP is ",dest_ip)
        
        if icmp_pkt:
            #src_ip = ip_pkt.src
            #dest_ip = ip_pkt.dst
            print("Packet from %s ke IP %a : count = %d", src_ip, dest_ip)
            
        # check IP Protocol and create a match for IP
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
            protocol = ip.proto
            self.mac_ip_to_dp[src][ip.src] = 0          
            #print("self.mac_ip_to_dp = ",self.mac_ip_to_dp)
            #print("len(self.mac_ip_to_dp[src] = ",len(self.mac_ip_to_dp[src]))
            if(len(self.mac_ip_to_dp[src]) > 30):
                self.ddos_oocurs=True
                print("DDos occur from src ", src)
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 110, match, [], msg.buffer_id, idle=0, hard=100*3*2)

                return-2
            
        # """Menangani paket yang datang ke controller."""
        # msg = ev.msg
        # datapath = msg.datapath
        # pkt = packet.Packet(msg.data)
        # dpid = datapath.id
        # eth = pkt.get_protocols(ethernet.ethernet)[0]
        # dst = eth.dst
        # src = eth.src
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser
        # in_port = msg.match['in_port']
        
        # #eth = pkt.get_protocol(ethernet.ethernet)
        # #if eth.ethertype == 0x0800:  # Hanya proses paket IPv4
        
        # ip_pkt = pkt.get_protocol(ipv4.ipv4)
        # icmp_pkt = pkt.get_protocol(icmp.icmp)
        # # Log untuk paket yang diterima
        # if ip_pkt and icmp_pkt:
            # src_ip = ip_pkt.src
            # dest_ip = ip_pkt.dst
            # self.packet_counts[src_ip] += 1
            # self.logger.info("Packet from %s ke IP %a : count = %d", src_ip, dest_ip, self.packet_counts[src_ip])
            
            # if self.packet_counts[src_ip] > self.threshold and src_ip not in self.email_sent:
                # # Kirim email notifikasi jika terjadi serangan
                # switch_id = ev.msg.datapath.id
                # subject = "Notifikasi SDN - Terjadi Serangan"
                # message = f"Terjadi serangan pada switch dengan ID {switch_id} "        
                # send_email(subject, message, self.to_email, self.from_email, self.password)
                # self.logger.info(f"Email notifikasi dikirim untuk switch ID: {switch_id}")
                
                # #self.send_email_alert(src_ip)
                # self.email_sent.add(src_ip)

    def install_default_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Membuat match untuk menangani semua paket (default flow)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        # Menambahkan flow ke switch untuk menangani semua paket
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        # """Menambahkan flow ke switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
        
    def send_email(subject, message, to_email, from_email, password):
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(from_email, password)
            msg = MIMEText(message)
            msg['Subject'] = subject
            msg['From'] = from_email
            msg['To'] = to_email
            server.sendmail(from_email, to_email, msg.as_string())
            server.quit()
            print("Email berhasil dikirim!")
        except Exception as e:
            print(f"Error mengirim email: {e}") 

#penjelasan program
# Event Handler  switch_features_handler : adalah event handler yang akan dipanggil ketika switch pertama kali terhubung ke controller. Di sini, kita akan menambahkan flow untuk memastikan bahwa paket yang datang dikirimkan ke controller untuk diproses lebih lanjut
# Flow Default match = parser.OFPMatch() digunakan untuk mencocokkan semua paket. kita bisa menambahkan kriteria untuk memfilter jenis paket tertentu (misalnya, berdasarkan IP, protokol, atau alamat MAC)
# Flow Default actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]: Ini mengatur bahwa setiap paket yang datang akan dikirim ke controller (menggunakan OFPP_CONTROLLER), dan tidak menggunakan buffer
# Menambahkan Flow ke Switch add_flow() menambahkan flow dengan prioritas tertentu ke dalam tabel aliran switch
# Packet In Handler adalah event handler yang akan dipanggil setiap kali paket masuk ke controller. kita dapat menambahkan logika untuk memproses paket tersebut di dalam fungsi ini
