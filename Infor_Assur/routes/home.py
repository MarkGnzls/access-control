from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

# Define a Blueprint for the home-related routes
home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def home():
    # If user is logged in, redirect to the dashboard; otherwise, show the homepage
    if current_user.is_authenticated:
        return redirect(url_for('home.dashboard'))
    return render_template('home.html')  # Render the homepage

@home_bp.route('/dashboard')
@login_required
def dashboard():
    # Render the dashboard page; pass user data to the template
    return render_template('dashboard.html', user=current_user)
