import os
import json
import gspread
from flask import Flask, render_template, request, redirect, url_for, session, flash
from google.oauth2.service_account import Credentials
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. Configuration and Google Sheets Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))

def get_gsheet_client():
    # Looks for the GOOGLE_CREDS environment variable on Render
    creds_json = os.environ.get('GOOGLE_CREDS')
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
    ]
    
    if creds_json:
        # Load from Render Environment Variable
        creds_dict = json.loads(creds_json)
        creds = Credentials.from_service_account_info(creds_dict, scopes=scopes)
    else:
        # Fallback for local testing (requires key.json in your folder)
        creds = Credentials.from_service_account_file("key.json", scopes=scopes)
        
    return gspread.authorize(creds)

# Connect to the Spreadsheet
# IMPORTANT: Your Google Sheet must be named "OfficeVoting" 
# and shared with the client_email in your JSON key.
client = get_gsheet_client()
spreadsheet = client.open("OfficeVoting")
user_sheet = spreadsheet.worksheet("Users")
poll_sheet = spreadsheet.worksheet("Polls")
vote_sheet = spreadsheet.worksheet("Votes")

# --- 2. Initial Setup Logic ---
def initialize_admin():
    """Ensure at least one admin exists in the sheet if empty."""
    users = user_sheet.get_all_records()
    if not any(u['username'] == 'admin' for u in users):
        hashed_pw = generate_password_hash('adminpass')
        # [username, password_hash, role]
        user_sheet.append_row(['admin', hashed_pw, 'admin'])
        print("Default admin user created in Google Sheet.")

# Initialize once on startup
initialize_admin()

# --- 3. Helper Decorators ---

def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def admin_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Access denied: Admins only.', 'danger')
            return redirect(url_for('user_dashboard') if session.get('user_id') else url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# --- 4. Routes ---

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        users = user_sheet.get_all_records()
        user = next((u for u in users if u['username'] == username), None)

        if user and check_password_hash(user['password_hash'], str(password)):
            session['user_id'] = user['username']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('admin_dashboard' if user['role'] == 'admin' else 'user_dashboard'))
        
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    polls = poll_sheet.get_all_records()
    return render_template('admin_dashboard.html', polls=polls)

@app.route('/admin/manage_users')
@login_required
@admin_required
def manage_users():
    users = user_sheet.get_all_records()
    return render_template('manage_users.html', users=users)

@app.route('/admin/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    
    users = user_sheet.get_all_records()
    if any(u['username'] == username for u in users):
        flash('Username already exists.', 'danger')
    else:
        hashed_pw = generate_password_hash(password)
        user_sheet.append_row([username, hashed_pw, role])
        flash(f'User {username} created successfully.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/create_poll', methods=['GET', 'POST'])
@login_required
@admin_required
def create_poll():
    if request.method == 'POST':
        title = request.form.get('title')
        options = request.form.get('options')
        
        all_polls = poll_sheet.get_all_records()
        new_id = len(all_polls) + 1
        # [id, title, options, is_published, results_published]
        poll_sheet.append_row([new_id, title, options, 'FALSE', 'FALSE'])
        
        flash(f'Poll "{title}" created!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_poll.html')

@app.route('/user')
@login_required
def user_dashboard():
    all_polls = poll_sheet.get_all_records()
    all_votes = vote_sheet.get_all_records()
    
    # Filter polls the user hasn't voted in yet
    voted_poll_ids = [str(v['poll_id']) for v in all_votes if str(v['user_id']) == session['user_id']]
    active_polls = [p for p in all_polls if p['is_published'] == 'TRUE' and str(p['id']) not in voted_poll_ids]
    
    return render_template('user_dashboard.html', active_polls=active_polls)

@app.route('/vote/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    all_polls = poll_sheet.get_all_records()
    poll = next((p for p in all_polls if int(p['id']) == poll_id), None)
    
    if not poll:
        flash("Poll not found.", "danger")
        return redirect(url_for('user_dashboard'))

    # Process options for the template
    poll['options_list'] = [opt.strip() for opt in str(poll['options']).split(',')]

    if request.method == 'POST':
        selected_option = request.form.get('option')
        # Save vote: [user_id, poll_id, selected_option]
        vote_sheet.append_row([session['user_id'], poll_id, selected_option])
        flash('Thank you! Your vote has been recorded.', 'success')
        return redirect(url_for('user_dashboard'))
    
    return render_template('vote.html', poll=poll)

# --- 5. Application Run ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)