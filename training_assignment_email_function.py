import smtplib
import os
from email.message import EmailMessage
from flask import url_for, current_app
from dotenv import load_dotenv
from itsdangerous import URLSafeSerializer

load_dotenv()

def get_serializer():
    return URLSafeSerializer(
        current_app.config['SECRET_KEY'], 
        salt="training-module"   
    )

def send_assignment_email(recipient_email, training_module, custom_message=None, app=None):
    recipient_email = recipient_email.strip()

   
    serializer = get_serializer()
    token = serializer.dumps({
        "module_id": training_module.id,
        "recipient": recipient_email
    })

    # secure link to training module
    training_link = url_for("routes.public_training_module", token=token, _external=True)

    # Email body
    plain_text_body = f"""
{training_module.description}

{custom_message if custom_message else ''}

This training module has been assigned to you.

Access it here: {training_link}
"""

    
    html_body = f"""
<p>{training_module.description}</p>
{f"<p>{custom_message}</p>" if custom_message else ""}
<p><strong>This training module has been assigned to you.</strong></p>
<p><a href="{training_link}" target="_blank">👉 Click here to start the training</a></p>
"""

    # Email setup
    msg = EmailMessage()
    msg['Subject'] = f"New Training Module Assigned: {training_module.title}"
    msg['From'] = f"TambuaPhish Awareness Training <info@tambuaphish.store>"
    msg['To'] = recipient_email

    msg.set_content(plain_text_body)
    msg.add_alternative(html_body, subtype='html')

    # SMTP
    smtp_server = os.getenv("HOST")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_username = os.getenv("MAIL_USERNAME")
    smtp_password = os.getenv("MAIL_PASSWORD")

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        print(f"✅ Assignment email sent to {recipient_email}")
    except Exception as e:
        print(f"❌ Error sending assignment email to {recipient_email}: {e}")
