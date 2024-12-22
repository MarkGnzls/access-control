#importing the required libararies
import os
import re
import secrets
import string
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

#creating the flask app
app = Flask(__name__)
app.secret_key = 'dagol'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///marks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

#creaeting the database
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#creating the user class
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_pic = db.Column(db.String(200), nullable=True)  # Store the file path for profile picture
    role = db.Column(db.String(50), nullable=False)

#User loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Helper function to check file type
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

#Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Query for the user with case-sensitive username matching
        user = User.query.filter(User.username == username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password!', 'danger')

    return render_template('login.html')

#Route for regiter
@app.route('/register', methods=['GET', 'POST'])
def register():
    admin_exists = User.query.filter_by(role='admin').first()

    # Prevent unauthorized users from accessing the registration page
    if current_user.is_authenticated and current_user.role != 'admin' and admin_exists:
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))

    suggested_password = None  # Default value for suggested password

    if request.method == 'POST':
        if 'suggest_password' in request.form:  # Check if Suggest Password button was clicked
            suggested_password = suggest_password()
            flash('Here is a suggested password!', 'info')
            return render_template('register.html', suggested_password=suggested_password)

        # Process user registration
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')

        # Check for duplicate username
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        # Validate password strength
        if not (len(password) >= 8 and any(c.isupper() for c in password) and
                any(c.islower() for c in password) and any(c.isdigit() for c in password)):
            flash('Password must have at least 8 characters, uppercase, lowercase, and a number.', 'danger')
            return redirect(url_for('register'))

        # Save the new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('User registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', suggested_password=suggested_password)

#Route for dashboard
@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    if current_user.role == 'admin':
        # Fetch all users for admin panel
        users = User.query.all()
    else:
        # Regular users don't need access to other users' data
        users = None

    return render_template('dashboard.html', users=users)

#Route for profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'username' in request.form:
            current_user.username = request.form['username']

        if 'password' in request.form and request.form['password']:
            current_user.password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')

        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                current_user.profile_pic = filename

        db.session.commit()
        flash('Profile updated successfully!', 'success')

    return render_template('profile.html', user=current_user)


# Route for Profile Edit
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # Get the form data
        username = request.form.get('username')
        password = request.form.get('password')
        profile_pic = request.files.get('profile_pic')

        # If username is changed
        if username and username != current_user.username:
            current_user.username = username

        # If password is provided and not empty
        if password:
            current_user.password = generate_password_hash(password)

        # Handle profile picture upload
        if profile_pic and allowed_file(profile_pic.filename):
            filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join('static/uploads', filename))
            current_user.profile_pic = filename  # Save only the filename

        # Commit changes to the database
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))  # Redirect to the dashboard after successful update

    return render_template('edit_profile.html')

#Route for adding user
@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash("You do not have permission to access this page.", 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Check for duplicates
        username_exists, password_exists = is_duplicate(username, password)
        if username_exists:
            flash('Username already exists!', 'danger')
            return redirect(url_for('add_user'))
        if password_exists:
            flash('Password has already been used!', 'danger')
            return redirect(url_for('add_user'))

        # Validate password strength
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and have no spaces.', 'danger')
            return redirect(url_for('add_user'))

        # Save the new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("New user added successfully!", 'success')
        return redirect(url_for('dashboard'))

    # Render the add user template
    return render_template('add_user.html')

#route for editing user
@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash("You do not have permission to access this page.")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        db.session.commit()

        flash("User details updated successfully!")
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html')

#route for deleting user
@app.route('/admin/delete_user/<int:user_id>', methods=['GET'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash("You do not have permission to delete a user.")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()

    flash("User deleted successfully!")
    return redirect(url_for('dashboard'))

#Helper functions
def is_duplicate(username, password):
    # Check if the username already exists
    username_exists = User.query.filter_by(username=username).first()
    
    # Check if the hashed version of the password already exists
    password_exists = User.query.filter(User.password == generate_password_hash(password, method='pbkdf2:sha256')).first()

    return username_exists, password_exists

#Helper funtion to check password strength
def is_strong_password(password):
    """
    Checks if the password meets the following medium strength requirements:
    - At least 8 characters long
    - Contains uppercase letters
    - Contains lowercase letters
    - Contains numbers
    - Contains no spaces
    - Optionally contains special characters
    """
    if (len(password) >= 8 and
        re.search(r'[A-Z]', password) and       # At least one uppercase letter
        re.search(r'[a-z]', password) and       # At least one lowercase letter
        re.search(r'\d', password) and          # At least one number
        not re.search(r'\s', password)):        # No spaces
        return True
    return False

#Helper function to suggest password
def suggest_password(length=12):
    """
    Generate a secure random password with uppercase, lowercase, digits, and optional special characters.
    """
    if length < 8:
        length = 8  # Minimum length of 8 characters

    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = string.punctuation.replace(' ', '')  # Exclude spaces

    # Ensure at least one of each character type
    password = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits)
    ]

    # Optionally add a special character
    if secrets.choice([True, False]):
        password.append(secrets.choice(special))

    # Fill the rest of the password
    all_chars = upper + lower + digits + special
    password += [secrets.choice(all_chars) for _ in range(length - len(password))]

    secrets.SystemRandom().shuffle(password)

    return ''.join(password)

#Route for viewing profile
@app.route('/user/profile/<int:user_id>')
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_profile.html', user=user)

#Route for logout
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Logs out the current user
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

#Route for error handling
@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


# Create DB
with app.app_context():
    db.create_all()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

#Run the app
if __name__ == '__main__':
    app.run(debug=True)
