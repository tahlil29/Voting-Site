import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. Configuration and App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))

# Fix for Render's PostgreSQL URL: change 'postgres://' to 'postgresql://'
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- 2. Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user') # 'admin' or 'user'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    options = db.Column(db.String(500), nullable=False) 
    is_published = db.Column(db.Boolean, default=False) 
    results_published = db.Column(db.Boolean, default=False) 
    
    def get_options_list(self):
        return [opt.strip() for opt in self.options.split(',')]

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    selected_option = db.Column(db.String(100), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'poll_id', name='_user_poll_uc'),)

# --- 3. Initial Setup Logic ---
def initialize_database():
    """Initializes tables and admin user."""
    # Create an initial 'admin' user if one does not exist
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', role='admin')
        admin_user.set_password('adminpass') 
        db.session.add(admin_user)
        db.session.commit()
        print("Initial 'admin' user created.")

# RUN THIS ON EVERY STARTUP:
with app.app_context():
    db.create_all()  # Ensures tables exist in PostgreSQL
    initialize_database() # Ensures admin user exists

# --- 4. Helper Decorators ---

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
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('user_dashboard') if session.get('user_id') else url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# --- 5. Routes ---

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('admin_dashboard' if user.role == 'admin' else 'user_dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/results')
@login_required
def results():
    published_polls = Poll.query.filter_by(results_published=True).all()
    poll_results = []
    for poll in published_polls:
        options = poll.get_options_list()
        total_votes = Vote.query.filter_by(poll_id=poll.id).count()
        option_counts = {}
        for option in options:
            count = Vote.query.filter_by(poll_id=poll.id, selected_option=option).count()
            percentage = (count / total_votes * 100) if total_votes > 0 else 0
            option_counts[option] = {'count': count, 'percentage': percentage}
        poll_results.append({'title': poll.title, 'total_votes': total_votes, 'counts': option_counts})
    return render_template('results.html', poll_results=poll_results)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    polls = Poll.query.all()
    return render_template('admin_dashboard.html', polls=polls)

@app.route('/admin/create_poll', methods=['GET', 'POST'])
@login_required
@admin_required
def create_poll():
    if request.method == 'POST':
        title = request.form.get('title')
        options = request.form.get('options')
        db.session.add(Poll(title=title, options=options))
        db.session.commit()
        flash('Poll created!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_poll.html')

@app.route('/admin/toggle_poll/<int:poll_id>/<action>')
@login_required
@admin_required
def toggle_poll(poll_id, action):
    poll = Poll.query.get_or_404(poll_id)
    if action == 'publish': poll.is_published = True
    elif action == 'unpublish': poll.is_published = False
    elif action == 'publish_results': poll.results_published = True
    elif action == 'delete':
        Vote.query.filter_by(poll_id=poll_id).delete()
        db.session.delete(poll)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/manage_users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    username, password, role = request.form.get('username'), request.form.get('password'), request.form.get('role', 'user')
    if User.query.filter_by(username=username).first():
        flash('User exists.', 'danger')
    else:
        u = User(username=username, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash(f'User {username} created.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/user')
@login_required
def user_dashboard():
    voted_ids = [v.poll_id for v in Vote.query.filter_by(user_id=session['user_id']).all()]
    active_polls = Poll.query.filter(Poll.is_published == True, ~Poll.id.in_(voted_ids)).all()
    return render_template('user_dashboard.html', active_polls=active_polls)

@app.route('/vote/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if Vote.query.filter_by(user_id=session['user_id'], poll_id=poll_id).first():
        flash('Already voted.', 'warning')
        return redirect(url_for('user_dashboard'))
    if request.method == 'POST':
        opt = request.form.get('option')
        if opt in poll.get_options_list():
            db.session.add(Vote(user_id=session['user_id'], poll_id=poll_id, selected_option=opt))
            db.session.commit()
            flash('Vote cast!', 'success')
            return redirect(url_for('user_dashboard'))
    return render_template('vote.html', poll=poll)

# --- 6. Application Run ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)