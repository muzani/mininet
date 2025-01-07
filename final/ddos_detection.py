from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from collections import defaultdict
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp

# Fungsi pengiriman email
import smtplib
from email.mime.text import MIMEText

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

class DDoSDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetection, self).__init__(*args, **kwargs)
        self.packet_counts = defaultdict(int)  # Penghitung paket per IP
        self.threshold = 20  # Ambang batas jumlah paket untuk DDoS
        self.email_sent = set()  # Mencatat IP yang sudah dikirimi email
        
        # Konfigurasi email
        self.from_email = "socialme.black@gmail.com"  # Ganti dengan email Anda
        self.password = "jyzemtausobocqjy"  # Ganti dengan password email Anda
        self.to_email = "zanimumu@gmail.com"  # Ganti dengan email penerima
   
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Menambahkan flow saat switch pertama kali terhubung ke controller."""
        self.logger.info("Switch connected: %s", ev.msg.datapath.id)
        
        #Kirim email notifikasi saat switch baru terhubung
        switch_id = ev.msg.datapath.id
        subject = "Notifikasi SDN - Switch Baru Terhubung"
        message = f"Switch dengan ID {switch_id} telah terhubung ke controller."        
        send_email(subject, message, self.to_email, self.from_email, self.password)
        self.logger.info(f"Email notifikasi dikirim untuk switch ID: {switch_id}")
        
        self.install_default_flow(ev.msg.datapath)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):                             
        """Menangani paket yang datang ke controller."""
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        dpid = datapath.id
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        #eth = pkt.get_protocol(ethernet.ethernet)
        #if eth.ethertype == 0x0800:  # Hanya proses paket IPv4
        
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_arp = pkt.get_protocol(arp.arp)
        
        if icmp_pkt:
            print("ICMP packet are receveived at dpid ",dpid," from src ",src, " to dst ",dst)
        elif(pkt_tcp): 
            print("TCP packet are receveived at dpid ",dpid," from src ",src, " to dst ",dst)
        elif(pkt_udp): 
            print("UDP packet are receveived at dpid ",dpid," from src ",src, " to dst ",dst)
        if(pkt_arp): 
            print("ARP packet are receveived at dpid ",dpid," from src ",src, " to dst ",dst)
        
        # Log untuk paket yang diterima
        if ip_pkt and icmp_pkt:
            src_ip = ip_pkt.src
            dest_ip = ip_pkt.dst
            self.packet_counts[src_ip] += 1
            self.logger.info("Packet from %s ke IP %a : count = %d", src_ip, dest_ip, self.packet_counts[src_ip])
            
            if self.packet_counts[src_ip] > self.threshold and src_ip not in self.email_sent:
                # Kirim email notifikasi jika terjadi serangan
                switch_id = ev.msg.datapath.id
                subject = "Notifikasi SDN - Terjadi Serangan"
                message = f"Terjadi serangan pada switch dengan ID {switch_id} "        
                send_email(subject, message, self.to_email, self.from_email, self.password)
                self.logger.info(f"Email notifikasi dikirim untuk switch ID: {switch_id}")
                
                #self.send_email_alert(src_ip)
                self.email_sent.add(src_ip)

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
        
     


#penjelasan program
# Event Handler  switch_features_handler : adalah event handler yang akan dipanggil ketika switch pertama kali terhubung ke controller. Di sini, kita akan menambahkan flow untuk memastikan bahwa paket yang datang dikirimkan ke controller untuk diproses lebih lanjut
# Flow Default match = parser.OFPMatch() digunakan untuk mencocokkan semua paket. kita bisa menambahkan kriteria untuk memfilter jenis paket tertentu (misalnya, berdasarkan IP, protokol, atau alamat MAC)
# Flow Default actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]: Ini mengatur bahwa setiap paket yang datang akan dikirim ke controller (menggunakan OFPP_CONTROLLER), dan tidak menggunakan buffer
# Menambahkan Flow ke Switch add_flow() menambahkan flow dengan prioritas tertentu ke dalam tabel aliran switch
# Packet In Handler adalah event handler yang akan dipanggil setiap kali paket masuk ke controller. kita dapat menambahkan logika untuk memproses paket tersebut di dalam fungsi ini

#protocol ping ICMP
# hping3 -S -p 80 --flood <IP_TARGET>
# hping3 -S -p 6653 -i u1000 192.168.1.3
# hping3 -1 -i u1000 192.168.1.3 #-i u1000: Mengirimkan paket setiap 1000 mikrodetik (1 ms). Anda dapat menyesuaikan nilainya
# hping3 -1 --flood 192.168.1.5
# sudo hping3 -1 --flood -d 1200 <target_ip> #-d 1200: Mengatur ukuran payload data dalam paket menjadi 1200 byte.

# -1: Mode ICMP (mengirimkan paket ICMP Echo Request seperti ping).
# --flood: Mengirimkan paket tanpa jeda, membuat banjir lalu lintas.
# <target_ip>: Alamat IP target yang akan diserang.