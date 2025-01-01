from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

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

        # Konfigurasi email
        self.from_email = "socialme.black@gmail.com"  # Ganti dengan email Anda
        self.password = "jyzemtausobocqjy"  # Ganti dengan password email Anda
        self.to_email = "zanimumu@gmail.com"  # Ganti dengan email penerima

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Kirim email notifikasi saat switch baru terhubung
        switch_id = ev.msg.datapath.id
        subject = "Notifikasi SDN - Switch Baru Terhubung"
        message = f"Switch dengan ID {switch_id} telah terhubung ke controller."
        
        send_email(subject, message, self.to_email, self.from_email, self.password)
        self.logger.info(f"Email notifikasi dikirim untuk switch ID: {switch_id}")
