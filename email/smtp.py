import smtplib
from email.mime.text import MIMEText

def send_email(subject, message, to_email, from_email, password):
    try:
        # Setup server SMTP
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Enable encryption
        server.login(from_email, password)

        # Buat email
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email

        # Kirim email
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print("Email berhasil dikirim!")
    except Exception as e:
        print(f"Error mengirim email: {e}")
