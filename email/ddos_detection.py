from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from collections import defaultdict
import smtplib
from email.mime.text import MIMEText

class DDoSDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetection, self).__init__(*args, **kwargs)
        self.packet_counts = defaultdict(int)  # Penghitung paket per IP
        self.threshold = 50  # Ambang batas jumlah paket untuk DDoS
        self.email_sent = set()  # Mencatat IP yang sudah dikirimi email

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
        msg = ev.msg
        pkt = packet.Packet(msg.data)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            self.packet_counts[src_ip] += 1
            self.logger.info("Packet from %s: count = %d", src_ip, self.packet_counts[src_ip])

            if self.packet_counts[src_ip] > self.threshold and src_ip not in self.email_sent:
                self.send_email_alert(src_ip)
                self.email_sent.add(src_ip)

    def send_email_alert(self, src_ip):
        """Mengirim notifikasi email jika serangan terdeteksi."""
        sender_email = "socialme.black@gmail.com"
        sender_password = "fjjuaalypwpwxyrn"
        recipient_email = "zanimumu@gmail.com"
        subject = "DDoS Alert Detected"
        body = f"Potensi serangan DDoS terdeteksi dari IP: {src_ip}.\nJumlah paket melebihi threshold."

        try:
            message = MIMEText(body)
            message["Subject"] = subject
            message["From"] = sender_email
            message["To"] = recipient_email

            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipient_email, message.as_string())
            self.logger.info("Email sent to %s", recipient_email)
        except Exception as e:
            self.logger.error("Failed to send email: %s", e)
