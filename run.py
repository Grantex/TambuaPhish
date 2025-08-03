from flask import Flask
from flask_mail import Mail
from config import Config
from routes import routes_bp
from models import db

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
mail = Mail(app)

# Register blueprint
app.register_blueprint(routes_bp)

# Create tables if not present
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)