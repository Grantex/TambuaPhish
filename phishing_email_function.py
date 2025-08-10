import smtplib
import os
from email.message import EmailMessage
from flask import url_for
from dotenv import load_dotenv

load_dotenv()

def send_phishing_email(recipient_email, template, campaign_id, recipient_id):
    recipient_email = recipient_email.strip()

    # ✅ Generate tracking link to the new Recipient tracking route
    tracking_link = url_for(
        'routes.track_link',
        campaign_id=campaign_id,
        recipient_id=recipient_id,
        _external=True
    )

    # ✅ Ensure HTML body is well-formed
    plain_text_body = f"""{template.email_body}

To learn more, click the link below:
{tracking_link}
"""

    html_body = f"""{template.email_body}
<br><br>
<p>To learn more, click the link below:</p>
<p><a href="{tracking_link}">Click here</a></p>
"""

    # ✅ Build email
    msg = EmailMessage()
    msg['Subject'] = template.subject.strip()
    msg['From'] = f"{template.sender_name.strip()} <info@tambuaphish.store>"
    msg['To'] = recipient_email

    # Set plain text & HTML
    msg.set_content(plain_text_body)
    msg.add_alternative(html_body, subtype='html')

    # ✅ SMTP (Zoho example)
    smtp_server = os.getenv("HOST")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_username = os.getenv("MAIL_USERNAME")
    smtp_password = os.getenv("MAIL_PASSWORD")

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        print(f"Email sent to {recipient_email}")
    except Exception as e:
        print(f"Error sending email to {recipient_email}: {e}")
