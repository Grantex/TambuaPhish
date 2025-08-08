from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Define CustomEmailTemplate first
class CustomEmailTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    template_name = db.Column(db.String(100), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    email_body = db.Column(db.Text, nullable=False)

# Then define User with the relationship
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)

    templates = db.relationship('CustomEmailTemplate', backref='creator', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'




class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    template_id = db.Column(db.Integer, db.ForeignKey('custom_email_template.id'), nullable=False)
      # NEW

    start_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    end_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default="Ongoing", nullable=False)

    # Relationships
    template = db.relationship('CustomEmailTemplate', backref=db.backref('campaigns', lazy=True))
    targets = db.relationship('Target', backref='campaign', lazy=True)
    user = db.relationship('User', backref=db.backref('campaigns', lazy=True))

    def mark_completed(self):
        self.status = "Completed"
        self.end_date = datetime.utcnow()



class Target(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)


class Recipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'))
    has_clicked = db.Column(db.Boolean, default=False)
    clicked_at = db.Column(db.DateTime, nullable=True)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)

    campaign = db.relationship('Campaign', backref=db.backref('recipients', lazy=True))
