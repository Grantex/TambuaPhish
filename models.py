from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Email template model
class CustomEmailTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    template_name = db.Column(db.String(100), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    email_body = db.Column(db.Text, nullable=False)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)

    templates = db.relationship('CustomEmailTemplate', backref='creator', lazy=True)
    modules = db.relationship("TrainingModule", back_populates="user")

    def __repr__(self):
        return f'<User {self.username}>'


# Campaign model 
class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    template_id = db.Column(db.Integer, db.ForeignKey('custom_email_template.id'), nullable=False)

    start_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    end_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default="Ongoing", nullable=False)

    # Relationships
    template = db.relationship('CustomEmailTemplate', backref=db.backref('campaigns', lazy=True))
    recipients = db.relationship('Recipient', backref='campaign', lazy=True)
    user = db.relationship('User', backref=db.backref('campaigns', lazy=True))

    def mark_completed(self):
        self.status = "Completed"
        self.end_date = datetime.now()


class Recipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    has_clicked = db.Column(db.Boolean, default=False)
    clicked_at = db.Column(db.DateTime, nullable=True)
    sent_at = db.Column(db.DateTime, default=datetime.now())


class TrainingModule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    format = db.Column(db.String(50), nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)  # stores links/materials
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    #Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship("User", back_populates="modules")



class Assignment(db.Model):
    __tablename__ = "assignments"

    id = db.Column(db.Integer, primary_key=True)
    
    # Link to training module
    module_id = db.Column(db.Integer, db.ForeignKey("training_module.id"), nullable=False)
    
    # Store emails (comma-separated string for now)
    emails = db.Column(db.Text, nullable=False)
    
    # Optional message
    message = db.Column(db.Text, nullable=True)
    
    # Timestamp
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship
    module = db.relationship("TrainingModule", backref=db.backref("assignments", lazy=True))
