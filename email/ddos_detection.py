from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from collections import defaultdict

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

class EmailNotificationRyu(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EmailNotificationRyu, self).__init__(*args, **kwargs)
        self.packet_counts = defaultdict(int)  # Penghitung paket per IP
        
        # Konfigurasi email
        self.from_email = "socialme.black@gmail.com"  # Ganti dengan email Anda
        self.password = "jyzemtausobocqjy"  # Ganti dengan password email Anda
        self.to_email = "zanimumu@gmail.com"  # Ganti dengan email penerima

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Kirim email notifikasi saat switch baru terhubung
        # switch_id = ev.msg.datapath.id
        # subject = "Notifikasi SDN - Switch Baru Terhubung"
        # message = f"Switch dengan ID {switch_id} telah terhubung ke controller."        
        # send_email(subject, message, self.to_email, self.from_email, self.password)
        # self.logger.info(f"Email notifikasi dikirim untuk switch ID: {switch_id}")
        
        #kirim email jika ada serangan
        self.install_default_flow(ev.msg.datapath)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == 0x0800:  # Hanya proses paket IPv4
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            
            if ip_pkt and icmp_pkt:
                src_ip = ip_pkt.src
                dest_ip = ip_pkt.dst
                self.packet_counts[src_ip] += 1
                self.logger.info("Packet from %s ke IP %a : count = %d", src_ip, dest_ip, self.packet_counts[src_ip])
                
                # if self.packet_counts[src_ip] > self.threshold and src_ip not in self.email_sent:
                    # self.send_email_alert(src_ip)
                    # self.email_sent.add(src_ip)

    def install_default_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=1)  # ICMP (ETH_TYPE=0x0800, IP_PROTO=1)()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
        
