from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# ---- User Model ----
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

# ---- Phishing Email Templates Model ----
# class PhishingEmailTemplates(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     template_name = db.Column(db.String(100), nullable=False, unique=True)
#     sender_name = db.Column(db.String(100), nullable=False)
#     subject_line = db.Column(db.String(200), nullable=False)
#     email_body = db.Column(db.Text, nullable=False)
#     cta_link = db.Column(db.String(200), nullable=False)

#     def __repr__(self):
#         return f'<PhishingEmailTemplates {self.template_name}>'
    

class CustomEmailTemplate(db.Model):
    """
    Model representing a custom email template created by the user.
    
    Attributes:
        id (int): Primary key for the template.
        template_name (str): The name assigned by the user to identify the template.
        sender_name (str): The name that appears in the 'From' field of the email.
        subject_line (str): The subject line of the email.
        body (str): The HTML/text content of the email body.
        cta_link (str): An optional call-to-action URL included in the email.
        created_at (datetime): Timestamp when the template was created.
        updated_at (datetime): Timestamp when the template was last updated.
    """
    __tablename__ = 'custom_email_templates'

    id = db.Column(db.Integer, primary_key=True)
    template_name = db.Column(db.String(100), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False)
    subject_line = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    cta_link = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<CustomEmailTemplate {self.template_name}>'