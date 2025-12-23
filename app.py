import os
import json
import gspread
from flask import Flask, render_template, request, redirect, url_for, session, flash
from google.oauth2.service_account import Credentials
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. Configuration and Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))

def get_gsheet_client():
    creds_json = os.environ.get('GOOGLE_CREDS')
    scopes = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
    if creds_json:
        creds_dict = json.loads(creds_json)
        creds = Credentials.from_service_account_info(creds_dict, scopes=scopes)
    else:
        creds = Credentials.from_service_account_file("key.json", scopes=scopes)
    return gspread.authorize(creds)

# Connect to Sheets
client = get_gsheet_client()
spreadsheet = client.open("OfficeVoting")
user_sheet = spreadsheet.worksheet("Users")
poll_sheet = spreadsheet.worksheet("Polls")
vote_sheet = spreadsheet.worksheet("Votes")

# Initialize Admin User if Sheet is Empty
with app.app_context():
    users = user_sheet.get_all_records()
    if not any(u['username'] == 'admin' for u in users):
        user_sheet.append_row(['admin', generate_password_hash('adminpass'), 'admin'])

# --- 2. Helper Decorators ---
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def admin_required(f):
    def wrap(*args, **kwargs):
        if 'role' not in session or session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# --- 3. Routes ---

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        users = user_sheet.get_all_records()
        user = next((u for u in users if u['username'] == username), None)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['username']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('admin_dashboard' if user['role'] == 'admin' else 'user_dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    polls = poll_sheet.get_all_records()
    return render_template('admin_dashboard.html', polls=polls)

@app.route('/results')
@login_required
def results():
    all_polls = poll_sheet.get_all_records()
    all_votes = vote_sheet.get_all_records()
    published_polls = [p for p in all_polls if str(p['results_published']).upper() == 'TRUE']
    poll_results = []
    for poll in published_polls:
        options = [opt.strip() for opt in str(poll['options']).split(',')]
        total_votes = sum(1 for v in all_votes if str(v['poll_id']) == str(poll['id']))
        counts = {opt: {'count': sum(1 for v in all_votes if str(v['poll_id']) == str(poll['id']) and v['selected_option'] == opt)} for opt in options}
        for opt in counts:
            counts[opt]['percentage'] = (counts[opt]['count'] / total_votes * 100) if total_votes > 0 else 0
        poll_results.append({'title': poll['title'], 'total_votes': total_votes, 'counts': counts})
    return render_template('results.html', poll_results=poll_results)

@app.route('/admin/create_poll', methods=['GET', 'POST'])
@login_required
@admin_required
def create_poll():
    if request.method == 'POST':
        title, options = request.form.get('title'), request.form.get('options')
        new_id = len(poll_sheet.get_all_records()) + 1
        poll_sheet.append_row([new_id, title, options, 'FALSE', 'FALSE'])
        flash('Poll created!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_poll.html')

@app.route('/admin/toggle_poll/<int:poll_id>/<action>')
@login_required
@admin_required
def toggle_poll(poll_id, action):
    all_polls = poll_sheet.get_all_records()
    # Find the row index (gspread is 1-indexed + header row)
    row_idx = next((i for i, p in enumerate(all_polls, 2) if int(p['id']) == poll_id), None)
    if row_idx:
        if action == 'publish': poll_sheet.update_cell(row_idx, 4, 'TRUE')
        elif action == 'unpublish': poll_sheet.update_cell(row_idx, 4, 'FALSE')
        elif action == 'publish_results': poll_sheet.update_cell(row_idx, 5, 'TRUE')
        elif action == 'delete': poll_sheet.delete_rows(row_idx)
    return redirect(url_for('admin_dashboard'))

@app.route('/user')
@login_required
def user_dashboard():
    polls = [p for p in poll_sheet.get_all_records() if str(p['is_published']).upper() == 'TRUE']
    voted_ids = [str(v['poll_id']) for v in vote_sheet.get_all_records() if v['user_id'] == session['user_id']]
    active_polls = [p for p in polls if str(p['id']) not in voted_ids]
    return render_template('user_dashboard.html', active_polls=active_polls)

@app.route('/vote/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    poll = next((p for p in poll_sheet.get_all_records() if int(p['id']) == poll_id), None)
    if request.method == 'POST':
        vote_sheet.append_row([session['user_id'], poll_id, request.form.get('option')])
        return redirect(url_for('user_dashboard'))
    poll['options_list'] = [opt.strip() for opt in str(poll['options']).split(',')]
    return render_template('vote.html', poll=poll)

@app.route('/admin/manage_users')
@login_required
@admin_required
def manage_users():
    return render_template('manage_users.html', users=user_sheet.get_all_records())

@app.route('/admin/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    username, password, role = request.form.get('username'), request.form.get('password'), request.form.get('role', 'user')
    user_sheet.append_row([username, generate_password_hash(password), role])
    return redirect(url_for('manage_users'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))