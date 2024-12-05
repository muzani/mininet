from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4

import logging
import smtplib
from email.mime.text import MIMEText

class DDoSDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetection, self).__init__(*args, **kwargs)
        self.packet_count = {}
        self.threshold = 1000  # Threshold paket per detik per IP
        self.email_sent = False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Ambil data paket
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        
        self.logger.info("ini paket datanya "+ pkt)
        
        
        # Parsing Ethernet dan IPv4
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        
        self.logger.info("ini jenis ip"+ ip)

        if not ip:  # Abaikan jika bukan paket IPv4
            return

        src_ip = ip.src

        # Hitung jumlah paket per sumber IP
        if src_ip in self.packet_count:
            self.packet_count[src_ip] += 1
        else:
            self.packet_count[src_ip] = 1

        # Periksa threshold
        if self.packet_count[src_ip] > self.threshold and not self.email_sent:
            self.logger.info(f"Serangan DDoS terdeteksi dari {src_ip}")
            self.send_email_alert(src_ip)
            self.email_sent = True

    def send_email_alert(self, attacker_ip):
        sender_email = "socialme.black@gmail.com"
        sender_password = "vmxexulzueqqcldp"
        recipient_email = "zanimumu@gmail.com"

        subject = "Peringatan: Serangan DDoS Terdeteksi"
        body = f"Serangan DDoS telah terdeteksi dari sumber IP: {attacker_ip}."

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

#test
#run
# ryu-manager ddos-identifier.py

#attack
# hping3 -S -p 80 --flood <IP_TARGET>
