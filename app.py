# app.py
import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------
# App Configuration
# -----------------------------
app = Flask(__name__)

# SECRET KEY (do NOT use os.urandom in production)
app.config['SECRET_KEY'] = os.environ.get(
    "SECRET_KEY", "dev-secret-key-change-this"
)

# PostgreSQL Database Config (Render compatible)
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace(
    "postgresql://", "postgresql+psycopg://"
)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# -----------------------------
# Database Models
# -----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user')  # admin / user

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

    __table_args__ = (
        db.UniqueConstraint('user_id', 'poll_id', name='_user_poll_uc'),
    )

# -----------------------------
# Initialize Database
# -----------------------------
def initialize_database():
    db.create_all()

    # Create default admin
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password('adminpass')  # CHANGE AFTER FIRST LOGIN
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created (username: admin, password: adminpass)")

# -----------------------------
# Decorators
# -----------------------------
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap


def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get('role') != 'admin':
            flash("Admins only", "danger")
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return wrap

# -----------------------------
# Auth Routes
# -----------------------------
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role

            flash("Login successful", "success")
            return redirect(
                url_for('admin_dashboard')
                if user.role == 'admin'
                else url_for('user_dashboard')
            )

        flash("Invalid credentials", "danger")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('login'))

# -----------------------------
# Admin Routes
# -----------------------------
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
        title = request.form['title']
        options = request.form['options']

        poll = Poll(title=title, options=options)
        db.session.add(poll)
        db.session.commit()

        flash("Poll created", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('create_poll.html')


@app.route('/admin/toggle_poll/<int:poll_id>/<action>')
@login_required
@admin_required
def toggle_poll(poll_id, action):
    poll = Poll.query.get_or_404(poll_id)

    if action == 'publish':
        poll.is_published = True
    elif action == 'unpublish':
        poll.is_published = False
    elif action == 'publish_results':
        poll.results_published = True
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
    username = request.form['username']
    password = request.form['password']
    role = request.form.get('role', 'user')

    if User.query.filter_by(username=username).first():
        flash("User already exists", "danger")
        return redirect(url_for('manage_users'))

    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    flash("User created", "success")
    return redirect(url_for('manage_users'))

# -----------------------------
# User Routes
# -----------------------------
@app.route('/user')
@login_required
def user_dashboard():
    user_id = session['user_id']

    voted = [v.poll_id for v in Vote.query.filter_by(user_id=user_id)]
    polls = Poll.query.filter(
        Poll.is_published == True,
        ~Poll.id.in_(voted)
    ).all()

    return render_template('user_dashboard.html', active_polls=polls)


@app.route('/vote/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)

    if request.method == 'POST':
        choice = request.form['option']

        vote = Vote(
            user_id=session['user_id'],
            poll_id=poll_id,
            selected_option=choice
        )
        db.session.add(vote)
        db.session.commit()

        flash("Vote submitted", "success")
        return redirect(url_for('user_dashboard'))

    return render_template('vote.html', poll=poll)


@app.route('/results')
@login_required
def results():
    polls = Poll.query.filter_by(results_published=True).all()
    data = []

    for poll in polls:
        options = poll.get_options_list()
        total = Vote.query.filter_by(poll_id=poll.id).count()

        counts = {}
        for opt in options:
            c = Vote.query.filter_by(
                poll_id=poll.id,
                selected_option=opt
            ).count()
            counts[opt] = {
                "count": c,
                "percentage": (c / total * 100) if total else 0
            }

        data.append({
            "title": poll.title,
            "total": total,
            "counts": counts
        })

    return render_template('results.html', poll_results=data)

# -----------------------------
# Run App
# -----------------------------
def start_server():
    with app.app_context():
        initialize_database()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


if __name__ == '__main__':
    start_server()
