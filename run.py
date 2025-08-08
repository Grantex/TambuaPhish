from flask import Flask
from flask_mail import Mail
from config import Config
from routes import routes_bp
from models import db
from flask_wtf import CSRFProtect


# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
mail = Mail(app)
csrf = CSRFProtect(app)
csrf.init_app(app)


# Register blueprints
app.register_blueprint(routes_bp)

# Run the app and create tables if they don't exist
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This ensures tables are created before running
    app.run(debug=True)
