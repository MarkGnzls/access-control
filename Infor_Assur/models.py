from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize SQLAlchemy
db = SQLAlchemy()

# User model
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)  # Primary Key
    username = db.Column(db.String(80), nullable=False, unique=True)  # Unique username
    email = db.Column(db.String(120), nullable=False, unique=True)  # Unique email
    password_hash = db.Column(db.String(128), nullable=False)  # Hashed password
    profile_picture = db.Column(db.String(200), default='default.png')  # Optional profile picture

    # Hash the password before saving
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Verify the password during login
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Represent the object
    def __repr__(self):
        return f"<User {self.username}>"
