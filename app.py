from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)

# Securely set up your database URI
raw_uri = os.getenv(
    'DATABASE_URL',
    'postgresql://socialsessions_user:lB0zaiK1CLY5aX9qJWMMmTdcye1ulsfd@dpg-cvkogeidbo4c73f9fleg-a/socialsessions'
)

# Fix for compatibility if needed
if raw_uri.startswith("postgres://"):
    raw_uri = raw_uri.replace("postgres://", "postgresql://", 1)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = raw_uri
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'changemefornow')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login_page"


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Init DB & Login
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login_page"

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='viewer')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    follow_up_date = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text)
    converted = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET'])
def login_page():
    return render_template("login.html")

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        login_user(user)
        return jsonify({'message': 'Login successful'})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out'})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(force=True)
    print("Received data:", data)
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    user = User(username=data['username'], role=data.get('role', 'admin'))
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route('/leads', methods=['POST'])
@login_required
def create_lead():
    data = request.get_json(force=True)
    lead = Lead(
        name=data['name'],
        email=data['email'],
        phone=data.get('phone'),
        follow_up_date=datetime.strptime(data['follow_up_date'], '%Y-%m-%d') if data.get('follow_up_date') else None,
        notes=data.get('notes')
    )
    db.session.add(lead)
    db.session.commit()
    return jsonify({'message': 'Lead created'})

# Run locally
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
import os

raw_uri = os.getenv(
    'DATABASE_URL',
    'postgresql://socialsessions_user:lB0zaiK1CLY5aX9qJWMMmTdcye1ulsfd@dpg-cvkogeidbo4c73f9fleg-a/socialsessions'
)

# Replace postgres:// with postgresql:// if necessary
if raw_uri.startswith("postgres://"):
    raw_uri = raw_uri.replace("postgres://", "postgresql://", 1)
    
app.config['SQLALCHEMY_DATABASE_URI'] = raw_uri

