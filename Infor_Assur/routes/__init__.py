from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from .routes.home import home_bp
from .routes.auth import auth_bp

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

    db.init_app(app)
    login_manager.init_app(app)

    # Register blueprints
    app.register_blueprint(home_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')

    return app
