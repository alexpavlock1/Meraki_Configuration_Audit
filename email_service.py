import os
import requests
import logging
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

def send_report_email(recipient_email, report_zip_path):
    """Send an email with the compliance report attached using Mailgun."""
    try:
        # Mailgun API credentials
        mailgun_api_key = os.getenv('MAILGUN_API_KEY', 'deb8a098cf75bc4cf0258a10f078da89-e298dd8e-3c6b8641')
        mailgun_domain = os.getenv('MAILGUN_DOMAIN', 'sandboxcaa0591492aa44d291adf735dfeacbe6.mailgun.org')  # e.g., mg.yourdomain.com
        sender_email = os.getenv('SENDER_EMAIL', 'meraki-reports@' + mailgun_domain)
        
        # API endpoint
        url = f"https://api.mailgun.net/v3/{mailgun_domain}/messages"
        
        # Create the email content
        subject = f'Meraki Compliance Report - {datetime.datetime.now().strftime("%Y-%m-%d")}'
        body = "Please find attached your Meraki Configuration Compliance Report.\n\n"
        
        # Prepare the multipart form data
        files = [("attachment", ("compliance_report.zip", open(report_zip_path, "rb").read()))]
        
        # Make the API request
        response = requests.post(
            url,
            auth=("api", mailgun_api_key),
            data={
                "from": sender_email,
                "to": recipient_email,
                "subject": subject,
                "text": body
            },
            files=files
        )
        
        # Check response
        response.raise_for_status()
        logging.debug(f"Sent compliance report email to {recipient_email}")
        return True
        
    except Exception as e:
        logging.error(f"Error sending email: {e}")
        return False

# Alternative SMTP implementation if you prefer
def send_report_email_smtp(recipient_email, report_zip_path):
    """Send an email with the compliance report attached using Mailgun SMTP."""
    try:
        import smtplib
        
        # Mailgun SMTP settings
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.mailgun.org')
        smtp_port = int(os.getenv('SMTP_PORT', 587))
        smtp_username = os.getenv('SMTP_USERNAME', 'postmaster@sandboxcaa0591492aa44d291adf735dfeacbe6.mailgun.org')
        smtp_password = os.getenv('SMTP_PASSWORD', 'Apallday922@')
        sender_email = os.getenv('SENDER_EMAIL', 'meraki-reports@your-domain.com')
        
        # Create a multipart message
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = recipient_email
        message['Subject'] = f'Meraki Compliance Report - {datetime.datetime.now().strftime("%Y-%m-%d")}'
        
        # Add body text
        body = "Please find attached your Meraki Configuration Compliance Report.\n\n"
        message.attach(MIMEText(body, 'plain'))
        
        # Attach the report zip file
        with open(report_zip_path, 'rb') as attachment:
            part = MIMEApplication(attachment.read(), Name='compliance_report.zip')
            part['Content-Disposition'] = f'attachment; filename="compliance_report.zip"'
            message.attach(part)
        
        # Connect to the SMTP server and send the email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(message)
        server.quit()
        
        logging.debug(f"Sent compliance report email to {recipient_email}")
        return True
    except Exception as e:
        logging.error(f"Error sending email: {e}")
        return False