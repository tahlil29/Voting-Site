# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. Configuration and App Initialization ---
app = Flask(__name__)
# IMPORTANT: Use a complex secret key for security
app.config['SECRET_KEY'] = os.urandom(24) 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- 2. Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user') # 'admin' or 'user'
    
    def set_password(self, password):
        """Hashes the password and sets the password_hash field."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    # Options stored as a comma-separated string
    options = db.Column(db.String(500), nullable=False) 
    is_published = db.Column(db.Boolean, default=False) 
    results_published = db.Column(db.Boolean, default=False) 
    
    def get_options_list(self):
        """Converts the comma-separated options string to a list."""
        return [opt.strip() for opt in self.options.split(',')]

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    selected_option = db.Column(db.String(100), nullable=False)
    
    # Ensures a user votes only once per poll
    __table_args__ = (db.UniqueConstraint('user_id', 'poll_id', name='_user_poll_uc'),)

# --- 3. Initial Setup Function ---
def initialize_database():
    """Creates all database tables and the initial admin user if they don't exist."""
    db.create_all() 
    
    # Create an initial 'admin' user if one does not exist
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', role='admin')
        admin_user.set_password('adminpass') # !!! CHANGE THIS FOR PRODUCTION !!!
        db.session.add(admin_user)
        db.session.commit()
        print("Initial 'admin' user created with password 'adminpass'")

# --- 4. Helper Functions (Decorators) ---

def login_required(f):
    """Decorator to require user login."""
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def admin_required(f):
    """Decorator to require admin role."""
    def wrap(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Access denied: Admins only.', 'danger')
            return redirect(url_for('user_dashboard') if session.get('user_id') else url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# --- 5. Shared Routes ---

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
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/results')
@login_required
def results():
    """Displays the results window for published polls."""
    published_polls = Poll.query.filter_by(results_published=True).all()
    
    poll_results = []
    
    for poll in published_polls:
        options = poll.get_options_list()
        total_votes = Vote.query.filter_by(poll_id=poll.id).count()
        
        option_counts = {}
        for option in options:
            count = Vote.query.filter_by(poll_id=poll.id, selected_option=option).count()
            percentage = (count / total_votes * 100) if total_votes > 0 else 0
            
            option_counts[option] = {
                'count': count,
                'percentage': percentage
            }
            
        poll_results.append({
            'title': poll.title,
            'total_votes': total_votes,
            'counts': option_counts
        })

    return render_template('results.html', poll_results=poll_results)

# --- 6. Admin Routes ---

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Admin home page: lists polls and management links."""
    polls = Poll.query.all()
    return render_template('admin_dashboard.html', polls=polls)

@app.route('/admin/create_poll', methods=['GET', 'POST'])
@login_required
@admin_required
def create_poll():
    """Admin can create a new poll."""
    if request.method == 'POST':
        title = request.form.get('title')
        options_string = request.form.get('options')
        
        new_poll = Poll(title=title, options=options_string)
        db.session.add(new_poll)
        db.session.commit()
        flash(f'Poll "{title}" created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('create_poll.html')

@app.route('/admin/toggle_poll/<int:poll_id>/<action>')
@login_required
@admin_required
def toggle_poll(poll_id, action):
    """Admin can publish/unpublish/publish results/delete polls."""
    poll = Poll.query.get_or_404(poll_id)
    
    if action == 'publish':
        poll.is_published = True
        flash(f'Poll "{poll.title}" is now open for voting.', 'success')
    elif action == 'unpublish':
        poll.is_published = False
        flash(f'Poll "{poll.title}" has been closed for voting.', 'info')
    elif action == 'publish_results':
        poll.results_published = True
        flash(f'Results for "{poll.title}" are now public.', 'success')
    elif action == 'delete':
        Vote.query.filter_by(poll_id=poll_id).delete()
        db.session.delete(poll)
        flash(f'Poll "{poll.title}" and all votes deleted.', 'danger')

    db.session.commit()
    return redirect(url_for('admin_dashboard'))

# --- Admin User Management Routes ---

@app.route('/admin/manage_users')
@login_required
@admin_required
def manage_users():
    """Displays the list of all users for admin management."""
    users = User.query.all()
    return render_template('manage_users.html', users=users)


@app.route('/admin/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    """Admin can create a new user (or admin) account."""
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role', 'user') 

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" already exists.', 'danger')
        return redirect(url_for('manage_users'))

    new_user = User(username=username, role=role)
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()
    flash(f'Account for {username} created successfully (Role: {role.upper()})', 'success')
    return redirect(url_for('manage_users'))


@app.route('/admin/toggle_user/<int:user_id>/<action>')
@login_required
@admin_required
def toggle_user(user_id, action):
    """Admin can delete a user or change their role."""
    user = User.query.get_or_404(user_id)
    
    if user_id == session['user_id'] and action in ['delete', 'demote']:
        admin_count = User.query.filter_by(role='admin').count()
        if admin_count == 1:
            flash("Cannot delete or demote the last remaining admin.", 'danger')
            return redirect(url_for('manage_users'))

    if action == 'promote':
        user.role = 'admin'
        flash(f'User {user.username} promoted to Admin.', 'info')
    elif action == 'demote':
        user.role = 'user'
        flash(f'User {user.username} demoted to User.', 'info')
    elif action == 'delete':
        Vote.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        flash(f'User {user.username} and all their votes have been deleted.', 'danger')
        
    db.session.commit()
    return redirect(url_for('manage_users'))

# --- 7. User Routes ---

@app.route('/user')
@login_required
def user_dashboard():
    """User home page: shows available polls to vote on."""
    user_id = session['user_id']
    
    voted_poll_ids = [v.poll_id for v in Vote.query.filter_by(user_id=user_id).all()]
    
    active_polls = Poll.query.filter(
        Poll.is_published == True, 
        ~Poll.id.in_(voted_poll_ids)
    ).all()
    
    return render_template('user_dashboard.html', active_polls=active_polls)

@app.route('/vote/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    """Handles the voting form and submission."""
    poll = Poll.query.get_or_404(poll_id)
    user_id = session['user_id']

    if Vote.query.filter_by(user_id=user_id, poll_id=poll_id).first():
        flash('You have already voted in this poll.', 'warning')
        return redirect(url_for('user_dashboard'))

    if not poll.is_published:
        flash('This poll is not currently open for voting.', 'danger')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        selected_option = request.form.get('option')
        
        if selected_option and selected_option in poll.get_options_list():
            new_vote = Vote(user_id=user_id, poll_id=poll_id, selected_option=selected_option)
            db.session.add(new_vote)
            db.session.commit()
            flash('Your vote has been cast successfully!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid option selected.', 'danger')

    return render_template('vote.html', poll=poll)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Allows a user to view and edit their profile (currently just password)."""
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        if new_password:
            user.set_password(new_password)
            db.session.commit()
            flash('Your password has been updated successfully!', 'success')
            return redirect(url_for('profile')) # Stay on profile page with success message
        else:
            flash('New password cannot be empty.', 'danger')

    return render_template('profile.html', user=user)

# --- 8. Application Run ---

if __name__ == '__main__':
    with app.app_context():
        initialize_database()
        
    app.run(debug=True)