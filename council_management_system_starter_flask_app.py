# Council Management System - Starter Flask App

# Project structure (single-repo starter)
# --------------------------------------
# /council_app/
#   ├── app.py                  # Flask app (entrypoint)
#   ├── config.py               # config (secret keys, upload paths)
#   ├── models.py               # SQLAlchemy models (User, Role, Permission, Payment, Notice)
#   ├── forms.py                # WTForms for registration/login/payment upload
#   ├── utils.py                # helper functions (send_email, send_sms placeholders)
#   ├── requirements.txt
#   ├── migrations/             # alembic/flask-migrate (optional)
#   ├── static/
#   │    └── uploads/           # uploaded photos & screenshots
#   └── templates/
#        ├── base.html
#        ├── index.html
#        ├── register.html
#        ├── login.html
#        ├── member_dashboard.html
#        ├── admin_dashboard.html
#        └── role_permissions.html

# ---------------------------
# Instructions to run (local)
# ---------------------------
# 1. Create venv: python -m venv venv
# 2. Activate: source venv/bin/activate (or venv\Scripts\activate)
# 3. pip install -r requirements.txt
# 4. export FLASK_APP=app.py && flask run
# 5. Open http://127.0.0.1:5000

# ---------------------------
# requirements.txt (minimal)
# ---------------------------
# flask
# flask_sqlalchemy
# flask_migrate
# flask_wtf
# wtforms
# flask_login
# email-validator
# pillow

# ---------------------------
# FILE: config.py
# ---------------------------
from pathlib import Path
import os

# Robustly determine base directory. In some sandboxed environments __file__ is not defined,
# so fall back to Path.cwd(). This prevents NameError: name '__file__' is not defined.
try:
    basedir = Path(__file__).resolve().parent
except NameError:
    basedir = Path.cwd()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me-to-secret')
    # Use string conversion to ensure SQLALCHEMY gets a proper URI
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f"sqlite:///{str(basedir / 'members.db')}" )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', str(basedir / 'static' / 'uploads'))
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# ---------------------------
# FILE: models.py
# ---------------------------
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

# Association table for Role <-> Permission
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    permissions = db.relationship('Permission', secondary=role_permissions, backref='roles')

    def has_permission(self, key):
        return any(p.key==key for p in self.permissions)

class Permission(db.Model):
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False)  # e.g., 'approve_payment'
    label = db.Column(db.String(255))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    father_name = db.Column(db.String(120))
    cnic = db.Column(db.String(20))
    phone = db.Column(db.String(30))
    whatsapp = db.Column(db.String(30))
    email = db.Column(db.String(120), unique=True)
    address = db.Column(db.String(255))
    designation = db.Column(db.String(80))
    password_hash = db.Column(db.String(255))
    photo = db.Column(db.String(255))
    status = db.Column(db.String(30), default='Active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    role = db.relationship('Role')

    payments = db.relationship('Payment', backref='user', lazy=True)
    notices = db.relationship('Notice', backref='user', lazy=True)

    def get_permissions(self):
        if self.role:
            return [p.key for p in self.role.permissions]
        return []

class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    month = db.Column(db.String(20))
    year = db.Column(db.Integer)
    amount = db.Column(db.Float)
    screenshot = db.Column(db.String(255))
    status = db.Column(db.String(30), default='Pending')  # Pending, Approved, Rejected
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notice(db.Model):
    __tablename__ = 'notices'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    type = db.Column(db.String(80))  # Warning, ShowCause, Violation
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------------------
# FILE: forms.py
# ---------------------------
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField, FloatField, IntegerField
from wtforms.validators import DataRequired, Length, Email, Optional

class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    father_name = StringField('Father Name', validators=[Optional()])
    cnic = StringField('CNIC', validators=[Optional()])
    phone = StringField('Phone', validators=[Optional()])
    whatsapp = StringField('WhatsApp', validators=[Optional()])
    email = StringField('Email', validators=[Optional(), Email()])
    address = StringField('Address', validators=[Optional()])
    designation = SelectField('Designation', choices=[('Member','Member'), ('Finance Secretary','Finance Secretary'), ('Chairman','Chairman')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    photo = FileField('Profile Photo', validators=[Optional()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    member_id = StringField('Member ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PaymentUploadForm(FlaskForm):
    month = StringField('Month', validators=[DataRequired()])
    year = IntegerField('Year', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired()])
    screenshot = FileField('Payment Screenshot', validators=[DataRequired()])
    submit = SubmitField('Upload')

# ---------------------------
# FILE: utils.py
# ---------------------------
import os
from werkzeug.utils import secure_filename
from flask import current_app

ALLOWED_EXT = {'png','jpg','jpeg','gif','pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT

def save_upload(file_storage, folder='uploads'):
    if file_storage and allowed_file(file_storage.filename):
        filename = secure_filename(file_storage.filename)
        upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], folder)
        os.makedirs(upload_path, exist_ok=True)
        filepath = os.path.join(upload_path, filename)
        file_storage.save(filepath)
        # return relative path
        return os.path.join('static','uploads', folder, filename)
    return None

# Placeholder functions for email / sms (implement integrations later)
def send_email(to, subject, body):
    # integrate Gmail API / SMTP here
    print(f"Sending email to {to}: {subject}")

def send_sms(number, message):
    # integrate Twilio or local SMS gateway here
    print(f"Sending SMS to {number}: {message}")

# ---------------------------
# FILE: app.py (main)
# ---------------------------
from flask import Flask, render_template, redirect, url_for, flash, request
from config import Config
from models import db, User, Role, Permission, Payment
from forms import RegisterForm, LoginForm, PaymentUploadForm
from utils import save_upload, send_email, send_sms
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import uuid

app = Flask(__name__)
app.config.from_object(Config)

# init
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Create initial permissions and roles if not exist
@app.before_first_request
def create_defaults():
    db.create_all()
    # create permissions
    perms = [
        ('view_members','View Members'),
        ('edit_members','Edit Members'),
        ('approve_payment','Approve Payment'),
        ('generate_notice','Generate Notice'),
        ('send_sms','Send SMS'),
        ('send_email','Send Email'),
        ('manage_roles','Manage Roles')
    ]
    for key,label in perms:
        if not Permission.query.filter_by(key=key).first():
            db.session.add(Permission(key=key, label=label))
    db.session.commit()

    # create Chairman role with all perms
    if not Role.query.filter_by(name='Chairman').first():
        chairman = Role(name='Chairman', description='Master admin')
        chairman.permissions = Permission.query.all()
        db.session.add(chairman)
    # create Member role
    if not Role.query.filter_by(name='Member').first():
        member_role = Role(name='Member', description='Regular member')
        # Members can view their own profile only (no global perms)
        db.session.add(member_role)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper to generate member id
def generate_member_id():
    return 'CMS-' + str(uuid.uuid4())[:8]

# Check permission decorator
from functools import wraps

def permission_required(key):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role and current_user.role.has_permission(key):
                return f(*args, **kwargs)
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('index'))
        return decorated_function
    return decorator

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        member_id = generate_member_id()
        password_hash = generate_password_hash(form.password.data)
        # auto assign role based on designation if role exists
        role = Role.query.filter_by(name=form.designation.data).first()
        user = User(member_id=member_id, name=form.name.data, father_name=form.father_name.data,
                    cnic=form.cnic.data, phone=form.phone.data, whatsapp=form.whatsapp.data,
                    email=form.email.data, address=form.address.data, designation=form.designation.data,
                    password_hash=password_hash, role=role)
        # save photo
        if form.photo.data:
            path = save_upload(form.photo.data, folder='photos')
            if path:
                user.photo = path
        db.session.add(user)
        db.session.commit()
        # notify admin or chairman
        chairman = Role.query.filter_by(name='Chairman').first()
        # (optional) send email to chairman(s)
        flash(f'Registered. Your Member ID: {member_id}', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(member_id=form.member_id.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Logged in', 'success')
            if user.role and user.role.name == 'Chairman':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('member_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/member')
@login_required
def member_dashboard():
    payments = Payment.query.filter_by(user_id=current_user.id).all()
    return render_template('member_dashboard.html', user=current_user, payments=payments)

@app.route('/upload_payment', methods=['GET','POST'])
@login_required
def upload_payment():
    form = PaymentUploadForm()
    if form.validate_on_submit():
        path = save_upload(request.files.get('screenshot'), folder='payments')
        payment = Payment(user_id=current_user.id, month=form.month.data, year=form.year.data,
                          amount=form.amount.data, screenshot=path, status='Pending')
        db.session.add(payment)
        db.session.commit()
        # Notify finance secretary(s)
        # send_email(...), send_sms(...)
        flash('Payment uploaded. Waiting for approval.', 'success')
        return redirect(url_for('member_dashboard'))
    return render_template('upload_payment.html', form=form)

@app.route('/admin')
@login_required
@permission_required('view_members')
def admin_dashboard():
    users = User.query.all()
    payments = Payment.query.order_by(Payment.uploaded_at.desc()).all()
    return render_template('admin_dashboard.html', users=users, payments=payments)

@app.route('/approve_payment/<int:pid>')
@login_required
@permission_required('approve_payment')
def approve_payment(pid):
    payment = Payment.query.get_or_404(pid)
    payment.status = 'Approved'
    db.session.commit()
    send_email(payment.user.email, 'Payment Approved', 'Your payment has been approved')
    send_sms(payment.user.phone, 'Your payment approved')
    flash('Payment Approved', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_payment/<int:pid>')
@login_required
@permission_required('approve_payment')
def reject_payment(pid):
    payment = Payment.query.get_or_404(pid)
    payment.status = 'Rejected'
    db.session.commit()
    send_email(payment.user.email, 'Payment Rejected', 'Please re-upload a clear screenshot')
    flash('Payment Rejected', 'warning')
    return redirect(url_for('admin_dashboard'))

# Roles & Permissions management UI
@app.route('/roles')
@login_required
@permission_required('manage_roles')
def roles():
    roles = Role.query.all()
    permissions = Permission.query.all()
    return render_template('role_permissions.html', roles=roles, permissions=permissions)

@app.route('/roles/update', methods=['POST'])
@login_required
@permission_required('manage_roles')
def update_roles():
    # expect form like role_{roleid}_perm_{permid} = 'on'
    for role in Role.query.all():
        selected = []
        for perm in Permission.query.all():
            key = f'role_{role.id}_perm_{perm.id}'
            if request.form.get(key):
                selected.append(perm)
        role.permissions = selected
    db.session.commit()
    flash('Roles updated', 'success')
    return redirect(url_for('roles'))

# Run
if __name__ == '__main__':
    app.run(debug=True)

# ---------------------------
# Templates: brief notes
# ---------------------------
# base.html -> navbar with login/logout; show current_user.role.name and member_id
# register.html -> uses RegisterForm
# login.html -> LoginForm
# member_dashboard.html -> show profile, uploaded payments, upload button
# admin_dashboard.html -> list of payments with Approve/Reject buttons
# role_permissions.html -> a table showing checkboxes for each role x permission; form POSTs to /roles/update

# ---------------------------
# Next steps I already prepared for you:
# 1. Set up email and SMS integration (Twilio or local gateway) when you provide API keys.
# 2. Implement automatic scheduled reminders (use celery or cron job). For now, reminders are placeholder functions in utils.py
# 3. Add PDF generation for notices (we can use reportlab or wkhtmltopdf) — I can add templates for auto notices.
# 4. Polish UI and add mobile-friendly styles (Bootstrap) — templates are placeholders.

# If you're ready, I can now:
# - provide the full HTML templates
# - implement notifications (email + SMS) with Twilio/Gmail
# - enable automatic scheduler for monthly checks (cron/celery)
# - deploy the app to Render/Heroku or provide instructions to run on a cheap VPS

# Tell me which one to do next and I will continue coding.
