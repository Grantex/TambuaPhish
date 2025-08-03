from flask_sqlalchemy import SQLAlchemy

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
class PhishingEmailTemplates(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    template_name = db.Column(db.String(100), nullable=False, unique=True)
    sender_name = db.Column(db.String(100), nullable=False)
    subject_line = db.Column(db.String(200), nullable=False)
    email_body = db.Column(db.Text, nullable=False)
    cta_link = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<PhishingEmailTemplates {self.template_name}>'