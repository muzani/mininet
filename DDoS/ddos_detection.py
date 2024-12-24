import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from collections import defaultdict
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
import time


class DDoSDetectionEmail(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetectionEmail, self).__init__(*args, **kwargs)
        self.packet_in_counter = defaultdict(lambda: defaultdict(int))  # Counter per sumber IP
        self.email_sent = defaultdict(set)  # Menyimpan IP yang sudah dikirimi email
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
        

        if ip:  # Hitung hanya jika paket memiliki header IPv4
            src_ip = ip.src
            self.packet_in_counter[dpid][src_ip] += 1

        # Log setiap detik
        if current_time - self.start_time >= 1:
            for dpid, src_counts in self.packet_in_counter.items():
                for src_ip, count in src_counts.items():
                    if count > 50:  # Threshold
                        self.logger.warning(
                            "Potensi serangan DDoS dari IP %s di switch %s: %d Packet-In per detik",
                            src_ip, dpid, count
                        )
                        # Kirim email jika belum terkirim sebelumnya
                        if src_ip not in self.email_sent[dpid]:
                            self.send_email_alert(src_ip, dpid, count)
                            self.email_sent[dpid].add(src_ip)

            # Reset counter dan waktu
            self.packet_in_counter = defaultdict(lambda: defaultdict(int))
            self.start_time = current_time

    def send_email_alert(self, src_ip, dpid, count):
        """Kirim notifikasi email tentang potensi serangan DDoS."""
        sender_email = "socialme.black@gmail.com"
        sender_password = "akcrzfnwnncrpygh"
        recipient_email = "zanimumu@gmail.com"

        subject = "DDoS Alert: Potensi Serangan Terdeteksi"
        body = (
            f"Potensi serangan DDoS terdeteksi:\n\n"
            f"Sumber IP: {src_ip}\n"
            f"Switch ID: {dpid}\n"
            f"Jumlah Packet-In: {count} per detik\n\n"
            f"Harap segera periksa sistem jaringan Anda."
        )
        
        msg = MIMEText(body, 'plain')
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = recipient_email
        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)
                self.logger.info("Email notifikasi berhasil dikirim.")
        except Exception as e:
            self.logger.error(f"Gagal mengirim email: {e}")
            
        # Konfigurasi email
        # message = MIMEMultipart()
        # message["From"] = sender_email
        # message["To"] = recipient_email
        # message["Subject"] = subject
        # message.attach(MIMEText(body, "plain"))
        # try:
            # # Koneksi ke server SMTP
            # server = smtplib.SMTP("smtp.gmail.com", 587)
            # server.starttls()
            # server.login(sender_email, sender_password)
            # server.sendmail(sender_email, recipient_email, message.as_string())
            # self.logger.info("Notifikasi email terkirim ke %s", recipient_email)
            # server.quit()
        # except Exception as e:
            # self.logger.error("Gagal mengirim email: %s", str(e))
