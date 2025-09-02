# Centralized location for app configurations such as database URIs, secret keys, and email configurations

import os
from datetime import timedelta
from dotenv import load_dotenv

# Loads environment variables from the .env file.

load_dotenv()

class Config:
   
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_fallback_secret_key'
    
   
    # 'DATABASE_URL' mapped from the .env file to this variable.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Mail Configuration (Zoho SMTP)
    MAIL_SERVER = 'smtp.zoho.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    
    # Retrieve mail credentials from the .env file
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # The default sender for emails
    MAIL_DEFAULT_SENDER = ('TambuaPhish', os.environ.get('MAIL_USERNAME'))