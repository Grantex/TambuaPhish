# Centralized location for app configurations such as database URIs, debug settings, and secret keys

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from the .env file.
# This must be called before accessing any environment variables.
load_dotenv()

class Config:
    # Use os.environ.get() to safely retrieve environment variables.
    # The second argument is a fallback value if the variable isn't found.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_fallback_secret_key'
    
    # Flask-SQLAlchemy looks for 'SQLALCHEMY_DATABASE_URI'
    # We map our 'DATABASE_URL' from the .env file to this variable.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Mail Configuration (Zoho SMTP)
    MAIL_SERVER = 'smtp.zoho.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    
    # Retrieve mail credentials from the environment
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # The default sender for emails
    MAIL_DEFAULT_SENDER = ('TambuaPhish', os.environ.get('MAIL_USERNAME'))