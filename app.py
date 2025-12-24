# app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from functools import wraps
from flask_socketio import SocketIO, emit
from datetime import datetime
    

# -------- FIREBASE --------
import firebase_admin
from firebase_admin import credentials, auth

# -------- APP CONFIG --------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
app.config["SECRET_KEY"] = "super-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------- FIREBASE INIT --------
if not firebase_admin._apps:
    cred = credentials.Certificate("firebase_key.json")
    firebase_admin.initialize_app(cred)

# -------- MODELS --------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)  # EMAIL
    full_name = db.Column(db.String(120), default="")
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(10), default="user")

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    options = db.Column(db.Text)
    allow_multiple = db.Column(db.Boolean, default=False)
    is_published = db.Column(db.Boolean, default=False)
    results_published = db.Column(db.Boolean, default=False)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    poll_id = db.Column(db.Integer)
    selected_option = db.Column(db.String(200))

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120))
    role = db.Column(db.String(10))
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    active = db.Column(db.Boolean, default=True)

# -------- DB INIT --------
with app.app_context():
    db.create_all()

    if not User.query.filter_by(username="admin@gmail.com").first():
        admin = User(
            username="admin@gmail.com",
            full_name="Admin",
            role="admin",
            password_hash=generate_password_hash("admin")
        )
        db.session.add(admin)
        db.session.commit()

# -------- DECORATORS --------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect(url_for("user_dashboard"))
        return f(*args, **kwargs)
    return wrapper

# -------- AUTH --------
@app.route("/")
@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/firebase-login", methods=["POST"])
def firebase_login():
    data = request.get_json()
    try:
        decoded = auth.verify_id_token(data["idToken"])
        email = decoded["email"]

        user = User.query.filter_by(username=email).first()
        if not user:
            user = User(username=email, full_name=email.split("@")[0])
            db.session.add(user)
            db.session.commit()

        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role

        return jsonify({
            "success": True,
            "redirect": "/admin" if user.role == "admin" else "/user"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 401

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@socketio.on("send_message")
def handle_message(data):
    if "user_id" not in session:
        return

    msg = ChatMessage(
        username=session.get("username"),
        role=session.get("role"),
        message=data["message"]
    )
    db.session.add(msg)
    db.session.commit()

    emit("receive_message", {
        "username": msg.username,
        "role": msg.role,
        "message": msg.message,
        "time": msg.timestamp.strftime("%H:%M")
    }, broadcast=True)

# -------- ADMIN --------
@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    polls = Poll.query.all()
    return render_template("admin_dashboard.html", polls=polls)

@app.route("/admin/create_poll", methods=["GET", "POST"])
@login_required
@admin_required
def create_poll():
    if request.method == "POST":
        poll = Poll(
            title=request.form["title"],
            options=request.form["options"],
            allow_multiple="allow_multiple" in request.form
        )
        db.session.add(poll)
        db.session.commit()
        return redirect(url_for("admin_dashboard"))
    return render_template("create_poll.html")

@app.route("/admin/edit_poll/<int:poll_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if request.method == "POST":
        poll.title = request.form["title"]
        poll.options = request.form["options"]
        poll.allow_multiple = "allow_multiple" in request.form
        db.session.commit()
        return redirect(url_for("admin_dashboard"))
    return render_template("edit_poll.html", poll=poll)

@app.route("/admin/delete_poll/<int:poll_id>")
@login_required
@admin_required
def delete_poll(poll_id):
    Poll.query.filter_by(id=poll_id).delete()
    Vote.query.filter_by(poll_id=poll_id).delete()
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/publish_poll/<int:poll_id>")
@login_required
@admin_required
def publish_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    poll.is_published = True
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/unpublish_poll/<int:poll_id>")
@login_required
@admin_required
def unpublish_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    poll.is_published = False
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/publish_results/<int:poll_id>")
@login_required
@admin_required
def publish_results(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    poll.results_published = True
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/manage_users")
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template("manage_users.html", users=users)

@app.route("/admin/toggle_user/<int:user_id>/<action>")
@login_required
@admin_required
def toggle_user(user_id, action):
    user = User.query.get_or_404(user_id)

    if action == "promote":
        user.role = "admin"
    elif action == "demote":
        user.role = "user"
    elif action == "delete" and user.username != "admin@gmail.com":
        db.session.delete(user)

    db.session.commit()
    return redirect(url_for("manage_users"))

@app.route("/admin/announcement", methods=["GET", "POST"])
@login_required
@admin_required
def announcement():
    ann = Announcement.query.first()

    if request.method == "POST":
        text = request.form.get("message")

        if ann:
            ann.message = text
            ann.active = True
        else:
            ann = Announcement(message=text)
            db.session.add(ann)

        db.session.commit()
        return redirect(url_for("admin_dashboard"))

    return render_template("announcement.html", ann=ann)


@app.route("/admin/announcement/delete")
@login_required
@admin_required
def delete_announcement():
    ann = Announcement.query.first()
    if ann:
        db.session.delete(ann)
        db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.context_processor
def inject_announcement():
    ann = Announcement.query.filter_by(active=True).first()
    return dict(global_announcement=ann)

# -------- USER --------
@app.route("/user")
@login_required
def user_dashboard():
    polls = Poll.query.filter_by(is_published=True).all()
    return render_template("user_dashboard.html", polls=polls)

@app.route("/vote/<int:poll_id>", methods=["GET", "POST"])
@login_required
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)

    if Vote.query.filter_by(user_id=session["user_id"], poll_id=poll_id).first():
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":
        choices = request.form.getlist("option")
        for c in choices:
            db.session.add(Vote(
                user_id=session["user_id"],
                poll_id=poll_id,
                selected_option=c
            ))
        db.session.commit()
        return redirect(url_for("user_dashboard"))

    options = [o.strip() for o in poll.options.split(",")]
    return render_template("vote.html", poll=poll, options=options)

@app.route("/results")
@login_required
def results():
    polls = Poll.query.filter_by(results_published=True).all()
    return render_template("results.html", polls=polls)

# -------- PROFILE --------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        user.full_name = request.form["full_name"]
        if request.form.get("password"):
            user.password_hash = generate_password_hash(request.form["password"])
        db.session.commit()
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)

# -------- RUN --------
if __name__ == "__main__":
    socketio.run(app, debug=True)

