from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_from_directory, g, current_app
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_babel import Babel, gettext as _, lazy_gettext as _l
from flask_migrate import Migrate

import os
import sys
import traceback
import random
from datetime import datetime, timedelta
import json
import time
import uuid
from functools import wraps
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, validators
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_migrate import Migrate
from datetime import datetime, timedelta
from functools import wraps
import os
import qrcode
from dotenv import load_dotenv
# --- Admin UI ---
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configure languages
app.config['LANGUAGES'] = {
    'en': 'English',
    'th': 'ไทย',
    'ja': '日本語'
}

# Make _ function available in templates
app.jinja_env.globals['_'] = _

# Configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY') or 'dev-key-change-this-in-production',
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'medicine.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ECHO=bool(os.environ.get('SQLALCHEMY_ECHO')),  # Enable SQL query logging
    UPLOAD_FOLDER=os.path.join('static', 'uploads'),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),  # Session expires in 1 day
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
)

# Ensure the instance folder exists
os.makedirs(os.path.join(app.root_path, 'instance'), exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
socketio = SocketIO()

# Initialize Babel without the app first
babel = Babel()

def get_locale():
    """Determine the best language to use for the request."""
    # Check session first
    lang = session.get('language')
    if lang:
        app.logger.info(f"[LANGUAGE DEBUG] Using language from session: {lang}")
        return lang
    
    # Check URL parameter
    if request.view_args and 'lang_code' in request.view_args:
        lang = request.view_args['lang_code']
        if lang in current_app.config['LANGUAGES']:
            app.logger.info(f"[LANGUAGE DEBUG] Using language from URL: {lang}")
            return lang
    
    # Check Accept-Language header
    if request.accept_languages:
        best_match = request.accept_languages.best_match(current_app.config['LANGUAGES'].keys())
        if best_match:
            app.logger.info(f"[LANGUAGE DEBUG] Using best match from Accept-Language: {best_match}")
            return best_match
    
    # Default to Thai
    app.logger.info("[LANGUAGE DEBUG] Using default language: th")
    return 'th'

def configure_babel_settings(app):
    """Configure Babel specific settings and initialize it."""
    # Configure Babel settings
    app.config.update(
        BABEL_DEFAULT_LOCALE='th',
        BABEL_TRANSLATION_DIRECTORY=os.path.join(app.root_path, 'translations'),
        BABEL_DOMAIN='messages',
        LANGUAGES={
            'en': 'English',
            'th': 'ไทย',
            'ja': '日本語'
        }
    )
    
    # Initialize Babel with the app
    babel.init_app(app, locale_selector=get_locale)
    
    # Make sure the translations directory exists
    translations_dir = os.path.join(app.root_path, 'translations')
    os.makedirs(translations_dir, exist_ok=True)

# Initialize extensions
def init_extensions(app):
    """Initialize Flask extensions."""
    # Initialize database
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Initialize CSRF protection
    csrf.init_app(app)
    
    # Configure Babel settings
    configure_babel_settings(app)
    
    # Initialize Socket.IO with the app and configure CORS
    socketio.init_app(
        app,
        cors_allowed_origins='*',
        async_mode='threading',
        logger=True,
        engineio_logger=True,
        ping_timeout=60,
        ping_interval=25,
        max_http_buffer_size=100 * 1024 * 1024,  # 100MB
        path='socket.io',  # Explicitly set the path to match client
        cors_credentials=True,
        allow_upgrades=True,
        cookie=None  # Don't set cookies for Socket.IO
    )
    
    # Set WTF_CSRF_CHECK_DEFAULT to False to allow non-POST requests without CSRF
    app.config['WTF_CSRF_CHECK_DEFAULT'] = False
    
    with app.app_context():
        # Create tables if they don't exist
        try:
            # Create the instance directory if it doesn't exist
            instance_path = os.path.join(app.root_path, 'instance')
            os.makedirs(instance_path, exist_ok=True)
            
            # Create the database file if it doesn't exist
            db_file = os.path.join(instance_path, 'medicine.db')
            if not os.path.exists(db_file):
                open(db_file, 'a').close()
            
            # Create all database tables
            db.create_all()
            app.logger.info('Database tables created/verified')
        except Exception as e:
            app.logger.error(f'Failed to create database tables: {str(e)}')
            raise

# Initialize extensions
init_extensions(app)

@app.before_request
def before_request():
    # Set CSRF token for all templates
    g.csrf_token = generate_csrf()

    # Skip for static files, set_language route, and API endpoints
    if request.endpoint in ('static', 'set_language', 'admin.index') or request.path.startswith(('/socket.io', '/api', '/admin', '/.well-known')):
        return

    # Get the language from the URL
    path_parts = request.path.strip('/').split('/')

    # If there's no language code in the URL, redirect to the default (Thai) version
    if not path_parts or path_parts[0] not in app.config['LANGUAGES']:
        clean_path = request.path.strip('/')
        new_url = f'/th/{clean_path}'.rstrip('/')
        if request.query_string:
            new_url += f'?{request.query_string.decode()}'
        return redirect(new_url)

    # If we get here, we have a valid language code in the URL
    lang_code = path_parts[0]

    # Set the language in the g object for template access
    g.lang_code = lang_code

    # Only update the session if the language has changed
    if session.get('language') != lang_code:
        app.logger.info(f"[LANGUAGE DEBUG] Language in session ('{session.get('language')}') does not match URL ('{lang_code}'). Updating session.")
        session['language'] = lang_code
        # Update Flask-Babel's locale
        from flask_babel import refresh
        refresh()

# Add language switcher route
@app.route('/set_language/<lang>')
def set_language(lang):
    try:
        # Validate language code
        if not lang or lang not in app.config['LANGUAGES']:
            lang = 'en'
        
        # Get the next URL from the query parameters or referrer
        next_url = request.args.get('next', '').strip()
        if not next_url or not next_url.startswith('/'):
            # If no next URL is provided, try to get it from the referrer
            referrer = request.referrer or ''
            if referrer:
                # Extract the path from the referrer URL
                from urllib.parse import urlparse
                parsed = urlparse(referrer)
                next_url = parsed.path
                if parsed.query:
                    next_url += '?' + parsed.query
        
        # If still no next URL, use the home page with the new language
        if not next_url or not next_url.startswith('/'):
            next_url = f'/{lang}'
        
        # Clean the next URL - remove any existing language code
        path_parts = next_url.strip('/').split('/')
        if path_parts and path_parts[0] in app.config['LANGUAGES']:
            path_parts.pop(0)  # Remove the language code
        
        # Rebuild the URL with the new language code
        clean_path = '/'.join(path_parts)
        if clean_path:
            next_url = f'/{lang}/{clean_path}'
        else:
            next_url = f'/{lang}'
        
        # Set the language in session
        session.permanent = True
        session['language'] = lang
        session.modified = True
        
        # Update Flask-Babel's locale
        from flask_babel import refresh
        refresh()
        
        # Create the response
        response = redirect(next_url)
        
        # Set a cookie that will be used by JavaScript
        response.set_cookie('language', lang, max_age=60*60*24*30, path='/')
        
        app.logger.info(f'Language set to: {lang}, redirecting to: {next_url}')
        return response
        
    except Exception as e:
        app.logger.error(f'Error setting language: {str(e)}', exc_info=True)
        flash(_('An error occurred while changing the language. Please try again.'), 'error')
        return redirect(url_for('home'))

# Make LANGUAGES and get_locale available in all templates
@app.context_processor
def inject_template_vars():
    from flask_babel import get_locale
    
    # Get the current locale
    current_locale = str(get_locale())
    
    # Get the current URL without the language prefix for language switching
    path_parts = [p for p in request.path.strip('/').split('/') if p]
    if path_parts and path_parts[0] in app.config['LANGUAGES']:
        current_path = '/' + '/'.join(path_parts[1:]) if len(path_parts) > 1 else '/'
    else:
        current_path = request.path
    
    return dict(
        LANGUAGES=app.config['LANGUAGES'],
        get_locale=get_locale,
        current_language=current_locale,
        current_lang=current_locale,  # For backward compatibility
        current_path=current_path,    # For building language switch URLs
        _=_,                         # Make _() available in templates
    )



# Configure CSRF error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({'error': 'CSRF token is missing or invalid'}), 400

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



# Online users tracking
online_users = {'patients': [], 'doctors': []}

# Ensure QR code directory exists
if not os.path.exists("static/qr_codes"):
    os.makedirs("static/qr_codes")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    # Allow duplicate emails (only username remains unique)
    email = db.Column(db.String(120))
    address = db.Column(db.Text)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

class Medicine(db.Model):
    id = db.Column(db.String(10), primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {'id': self.id, 'name': self.name}

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(100), nullable=False)
    sender_type = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {'id': self.id, 'sender': self.sender, 'sender_type': self.sender_type, 'message': self.message, 'timestamp': self.timestamp.isoformat()}

class Patient(db.Model):
    __tablename__ = 'patient'
    
    id = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    symptoms = db.Column(db.Text, nullable=False)
    allergy = db.Column(db.Text, nullable=True)
    phone = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='waiting')
    medicine = db.Column(db.String(100), nullable=True)
    medicine_id = db.Column(db.String(10), nullable=True)
    prescribed_time = db.Column(db.DateTime, nullable=True)
    qr_code = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __init__(self, **kwargs):
        # Generate ID first
        if 'id' not in kwargs:
            # Format: P + YYMMDD + 4 random digits
            timestamp = datetime.now().strftime('%y%m%d')
            random_digits = str(random.randint(1000, 9999))
            kwargs['id'] = f"P{timestamp}{random_digits}"
        
        # Set created_at if not provided
        if 'created_at' not in kwargs:
            kwargs['created_at'] = datetime.utcnow()
            
        super(Patient, self).__init__(**kwargs)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'symptoms': self.symptoms,
            'allergy': self.allergy if self.allergy else '-',
            'phone': self.phone,
            'status': self.status,
            'medicine': self.medicine,
            'medicine_id': self.medicine_id,
            'prescribed_time': self.prescribed_time.isoformat() if self.prescribed_time else None,
            'qr_code': self.qr_code,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# ----------
# Admin interface (lightweight DB viewer)
# ----------
admin = Admin(app, name='Database', template_mode='bootstrap4', url='/admin')
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Medicine, db.session))
admin.add_view(ModelView(Patient, db.session))
admin.add_view(ModelView(ChatMessage, db.session))

# Decorators
def doctor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'doctor':
            return jsonify({'error': 'Doctor access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Forms
class LoginForm(FlaskForm):
    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        # Initialize form fields with current translations
        self.username.label.text = _('username')
        self.password.label.text = _('password')
        self.role.label.text = _('role')
        self.submit.label.text = _('login')
        
        # Set choices with current translations
        self.role.choices = [
            ('', _('select_role') + '...'),  # Add ellipsis to indicate selection needed
            ('doctor', _('doctor')),
            ('patient', _('patient'))
        ]
        
        # Update validation messages
        self.username.validators = [
            validators.DataRequired(message=_('please_enter_your_username')),
            validators.Length(min=3, max=80, message=_('username_length_validation'))
        ]
        self.password.validators = [
            validators.DataRequired(message=_('please_enter_your_password')),
            validators.Length(min=6, message=_('password_length_validation'))
        ]
        # Make role required only on form submission
        self.role.validators = [
            validators.Optional()  # Make role optional initially
        ]

    username = StringField('', render_kw={"placeholder": _('enter_username')})
    password = PasswordField('', render_kw={"placeholder": _('enter_password')})
    role = SelectField(choices=[], validators=[validators.Optional()])
    submit = SubmitField('')
    
    def validate(self, extra_validators=None):
        # Only run validation if the form is being submitted
        if not self.is_submitted():
            return True
            
        # Call the parent's validate method
        if not super(LoginForm, self).validate(extra_validators=extra_validators):
            return False
            
        # Add custom validation for the role field only when the form is submitted
        if not self.role.data:
            self.role.errors.append(_('please_select_role'))
            return False
            
        return True

class RegistrationForm(FlaskForm):
    username = StringField(_l('username'), validators=[validators.DataRequired(), validators.Length(min=3, max=80)])
    password = PasswordField(_l('password'), validators=[validators.DataRequired(), validators.Length(min=6)])
    confirm_password = PasswordField(_l('confirm_password'), validators=[validators.DataRequired(), validators.EqualTo('password', message=_l('passwords_must_match'))])
    role = SelectField(_l('role'), choices=[('', _l('select_role')), ('doctor', _l('doctor')), ('patient', _l('patient'))], validators=[validators.DataRequired()])
    name = StringField(_l('name'), validators=[validators.DataRequired()])
    phone = StringField(_l('phone'), validators=[validators.DataRequired()])
    email = StringField(_l('email'), validators=[validators.Email(), validators.Optional()])
    submit = SubmitField(_l('register'))

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise validators.ValidationError(_l('That username is already taken. Please choose another.'))

    # Email can be duplicated, so only validate format (handled by field validators)

# Routes

@app.route('/')
def index():
    return redirect(url_for('home', lang_code='th'))

@app.route('/test-translation')
def test_translation():
    """Test route to verify translations are working."""
    from flask_babel import gettext
    
    test_text = gettext('please_specify_allergies')
    app.logger.info(f"[TRANSLATION TEST] 'please_specify_allergies' in {session.get('language', 'th')}: {test_text}")
    
    return jsonify({
        'language': session.get('language', 'th'),
        'translation': test_text,
        'all_languages': dict(app.config['LANGUAGES'])
    })

@app.route('/<lang_code>/')
def home(lang_code=None):
    # Determine the language code if it wasn't supplied (edge-case when URL build
    # omitted it). Fallback order: g.lang_code → session["language"] → default 'en'.
    if lang_code is None:
        lang_code = getattr(g, 'lang_code', None) or session.get('language', 'en')

    return render_template('index.html', lang_code=lang_code)

@app.route('/login', defaults={'lang_code': None}, methods=['GET', 'POST'])
@app.route('/<lang_code>/login', methods=['GET', 'POST'])
def login(lang_code=None):
    # Ensure lang_code is defined
    if lang_code is None:
        lang_code = getattr(g, 'lang_code', None) or session.get('language', 'th')
    
    # Update session language if needed
    if lang_code != session.get('language'):
        session['language'] = lang_code
        app.logger.info(f"[LANGUAGE DEBUG] Updated session language to: {lang_code}")
    
    # Initialize form with appropriate translations
    form = LoginForm()
    
    # Only process the form if it's a POST request (form submission)
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            role = form.role.data
            
            user = User.query.filter_by(username=username, role=role).first()
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                next_page = request.args.get('next')
                if next_page:
                    return redirect(next_page)
                else:
                    # Redirect to the appropriate page with the language prefix
                    return redirect(url_for(f'{role}_page', lang_code=lang_code))
            else:
                # Clear any existing flash messages before setting a new one
                session.pop('_flashes', None)
                flash(_('Invalid username, password, or role'), 'danger')
        # If we get here, the form had validation errors
        # The form will be re-rendered with the validation messages
    
    # Clear any existing flash messages before rendering the template
    session.pop('_flashes', None)
    # Always render the login template, regardless of authentication status
    return render_template('login.html', form=form, lang_code=lang_code)

@app.route('/create_test_users')
def create_test_users():
    """Create test patient and doctor users (idempotent). Returns JSON with credentials."""
    try:
        created = []
        users_to_create = [
            {
                'username': 'demo_patient',
                'password': 'patient123',
                'role': 'patient',
                'name': 'Demo Patient',
                'phone': '0800000001',
                'email': 'demo.patient@example.com'
            },
            {
                'username': 'demo_doctor',
                'password': 'doctor123',
                'role': 'doctor',
                'name': 'Demo Doctor',
                'phone': '0800000002',
                'email': 'demo.doctor@example.com'
            }
        ]
        for u in users_to_create:
            if not User.query.filter_by(username=u['username']).first():
                user = User(
                    username=u['username'],
                    password_hash=generate_password_hash(u['password']),
                    role=u['role'],
                    name=u['name'],
                    phone=u['phone'],
                    email=u['email']
                )
                db.session.add(user)
                created.append({'username': u['username'], 'password': u['password'], 'role': u['role']})
        db.session.commit()
        return jsonify({'success': True, 'created': created}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# Original single test patient route (deprecated but kept for compatibility)
@app.route('/create_test_patient_user')
def create_test_patient_user():
    """Create a test patient user for development purposes"""
    try:
        # Check if test user already exists
        test_username = 'test_patient'
        if User.query.filter_by(username=test_username).first():
            return jsonify({
                'success': False,
                'message': 'Test patient user already exists',
                'credentials': {
                    'username': test_username,
                    'password': 'test1234',
                    'role': 'patient'
                }
            })
        
        # Create test patient user
        test_user = User(
            username=test_username,
            password_hash=generate_password_hash('test1234'),
            role='patient',
            name='ทดสอบ ผู้ป่วย',
            phone='0812345678',
            email='test.patient@example.com'
        )
        
        db.session.add(test_user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'สร้างผู้ใช้ทดสอบสำเร็จ',
            'credentials': {
                'username': test_username,
                'password': 'test1234',
                'role': 'patient'
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'เกิดข้อผิดพลาด: {str(e)}'
        }), 500

@app.route('/logout')
@app.route('/<lang_code>/logout')
@login_required
def logout(lang_code=None):
    if lang_code is None:
        lang_code = getattr(g, 'lang_code', None) or session.get('language', 'th')
    # Get the current language from the g object or fall back to session/default
    lang_code = g.get('lang_code', session.get('language', 'th'))
    logout_user()
    return redirect(url_for('login', lang_code=lang_code))

@app.route('/<lang_code>/register', methods=['GET', 'POST'])
def register(lang_code=None):
    # Ensure lang_code is defined
    if lang_code is None:
        lang_code = getattr(g, 'lang_code', None) or session.get('language', 'th')
    if current_user.is_authenticated:
        # User already logged in – jump to their role-specific page instead of home
        return redirect(url_for('home', lang_code=lang_code))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data,
            name=form.name.data,
            phone=form.phone.data,
            email=form.email.data,
            role=form.role.data,
            password_hash=hashed_password
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash(_('Your account has been created! You can now log in.'), 'success')
            return redirect(url_for('login', lang_code=lang_code))
        except IntegrityError:
            db.session.rollback()
            flash(_('That username or email is already registered.'), 'danger')
    
    return render_template('register.html', title=_('Register'), form=form, lang_code=lang_code)

@app.route('/patient')  # Default route without language code
@app.route('/<lang_code>/patient')  # Route with language code
@login_required
def patient_page(lang_code='th'):  # Default to Thai if no language code provided
    # Add any patient-specific data fetching here if needed
    # Ensure the language is in the session
    if lang_code not in app.config['LANGUAGES']:
        lang_code = 'th'  # Fallback to Thai if invalid language code
    return render_template('patient.html')

@app.route('/doctor')  # Default route without language code
@app.route('/<lang_code>/doctor')  # Route with language code
@login_required
@doctor_required
def doctor_page(lang_code='th'):  # Default to Thai if no language code provided
    patients = Patient.query.all()
    medicines = [m.to_dict() for m in Medicine.query.all()]
    stats = {
        'waiting_patients': len([p for p in patients if p.status == 'waiting']),
        'completed_patients': len([p for p in patients if p.status == 'done'])
    }
    return render_template('doctor.html',
                         patients=[p.to_dict() for p in patients],
                         medicines=medicines,
                         stats=stats)

# SocketIO Events
# Global dictionary to track connected users
connected_users = {}

@socketio.on('connect')
def handle_connect():
    app.logger.info(f'Client connected: {request.sid}')
    emit('connection_response', {'data': 'Connected', 'sid': request.sid})

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info(f'Client disconnected: {request.sid}')
    # Clean up the user from connected_users
    for username, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[username]
            break
    emit_online_users_update()

@socketio.on('join_room')
def on_join_room(data):
    try:
        if not data or 'username' not in data or 'role' not in data:
            app.logger.error('Invalid join_room data')
            return {'status': 'error', 'message': 'Username and role are required'}
            
        username = data['username']
        role = data['role']
        room = 'waiting_room'
        
        app.logger.info(f'User {username} (role: {role}) joining room: {room}')
        
        # Store the user's room in the session
        if 'socket_rooms' not in session:
            session['socket_rooms'] = []
        
        if room not in session['socket_rooms']:
            session['socket_rooms'].append(room)
        
        # Store user in connected_users
        connected_users[username] = request.sid
        
        join_room(room)
        emit('user_joined', {
            'username': username, 
            'role': role, 
            'message': f'{username} has joined the room.',
            'timestamp': datetime.utcnow().isoformat(),
            'online_users': list(connected_users.keys())
        }, room=room)
        
        emit_online_users_update()
        return {'status': 'success', 'room': room}
        
    except Exception as e:
        app.logger.error(f'Error in on_join_room: {str(e)}')
        return {'status': 'error', 'message': str(e)}

@socketio.on('send_message')
def handle_message(data):
    try:
        if not data or 'message' not in data or 'sender' not in data or 'sender_type' not in data:
            app.logger.error('Invalid message data')
            return {'status': 'error', 'message': 'Message, sender, and sender_type are required'}
        
        app.logger.info(f'New message from {data["sender"]}')
        
        # Save message to database
        message = ChatMessage(
            sender=data['sender'],
            sender_type=data['sender_type'],
            message=data['message']
        )
        db.session.add(message)
        db.session.commit()
        
        # Prepare message data
        message_data = message.to_dict()
        message_data['timestamp'] = message.timestamp.isoformat()
        
        # Broadcast the message to all clients in the room
        emit('new_message', message_data, room='waiting_room')
        return {'status': 'success', 'message_id': message.id}
        
    except Exception as e:
        app.logger.error(f'Error in handle_message: {str(e)}')
        return {'status': 'error', 'message': str(e)}

def emit_online_users_update():
    try:
        room = 'waiting_room'
        # Get all connected users in the room
        online_users = list(connected_users.keys())
        app.logger.info(f'Sending online users update: {online_users}')
        
        # Emit to all clients in the room
        emit('online_users_update', {
            'count': len(online_users),
            'users': online_users,
            'timestamp': datetime.utcnow().isoformat()
        }, room=room)
    except Exception as e:
        app.logger.error(f'Error in emit_online_users_update: {str(e)}')
    # This line was causing a syntax error and has been removed
    # socketio.emit('online_users_update', user_count, namespace='/doctor')

# API Endpoints
@app.route('/api/submit_patient', methods=['POST'])
def submit_patient():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': _('No data provided')}), 400
            
        # Get language code from URL or default to Thai
        lang_code = request.args.get('lang_code', 'th')
            
        # Validate required fields
        required_fields = ['name', 'age', 'gender', 'phone', 'symptoms']
        field_labels = {
            'name': _('full_name'),
            'age': _('age'),
            'gender': _('gender'),
            'phone': _('phone'),
            'symptoms': _('symptoms')
        }
        
        for field in required_fields:
            if field not in data or not str(data[field]).strip():
                error_msg = f'Missing required field: {field}'
                app.logger.error(error_msg)
                return jsonify({
                    'success': False,
                    'error': f'กรุณากรอก{field_labels.get(field, field)}',
                    'details': error_msg
                }), 400
        
        # Validate phone number format (10 digits)
        phone = ''.join(filter(str.isdigit, data['phone']))
        if len(phone) != 10 or not phone.isdigit():
            error_msg = f'Invalid phone number format: {data["phone"]}'
            app.logger.error(error_msg)
            return jsonify({
                'success': False,
                'error': 'หมายเลขโทรศัพท์ต้องเป็นตัวเลข 10 หลัก',
                'details': error_msg
            }), 400
        
        try:
            # Create patient record
            patient = Patient(
                name=data['name'].strip(),
                phone=phone,
                symptoms=data['symptoms'].strip(),
                allergy=data.get('allergy', '').strip() or None,
                status='waiting'  # Initial status is 'waiting' until doctor prescribes
            )
            
            # Add and commit the patient
            db.session.add(patient)
            db.session.commit()
            
            app.logger.info(f'Successfully created patient with ID: {patient.id}')
            
            # Broadcast new patient to all connected doctors
            socketio.emit('new_patient', patient.to_dict(), broadcast=True, namespace='/doctor')
            
            return jsonify({
                'success': True,
                'patient_id': patient.id,
                'message': 'กรุณารอให้แพทย์ตรวจสอบและสั่งยา',
                'status': 'waiting'
            })
                
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Database error in transaction: {str(e)}')
            app.logger.error(f'Traceback: {traceback.format_exc()}')
            return jsonify({
                'success': False,
                'error': 'เกิดข้อผิดพลาดในการบันทึกข้อมูลผู้ป่วยในฐานข้อมูล',
                'details': str(e),
                'type': type(e).__name__
            }), 500
            
    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        app.logger.error(f'Unexpected error in submit_patient: {error_msg}')
        app.logger.error(f'Error type: {type(e).__name__}')
        app.logger.error(f'Traceback: {traceback.format_exc()}')
        return jsonify({
            'success': False,
            'error': 'เกิดข้อผิดพลาดที่ไม่คาดคิดในการประมวลผลคำขอ',
            'details': error_msg,
            'type': type(e).__name__
        }), 500


@app.route('/get_patients')
@login_required
def get_patients():
    try:
        # Get language code from URL or default to Thai
        lang_code = request.args.get('lang_code', 'th')
        
        # Get status filter if provided
        status = request.args.get('status')
        query = Patient.query
        
        if status:
            query = query.filter_by(status=status)
            
        patients = query.order_by(Patient.created_at.desc()).all()
        
        # Convert patients to dictionary format
        patients_list = []
        for patient in patients:
            patient_dict = {
                'id': patient.id,
                'name': patient.name,
                'symptoms': patient.symptoms,
                'allergy': patient.allergy or _('none'),
                'phone': patient.phone,
                'status': patient.status or 'waiting',
                'medicine': patient.medicine or '',
                'medicine_id': patient.medicine_id or '',
                'prescribed_time': patient.prescribed_time.isoformat() if patient.prescribed_time else None,
                'qr_code': patient.qr_code or '',
                'created_at': patient.created_at.isoformat() if patient.created_at else None
            }
            patients_list.append(patient_dict)
        
        return jsonify(patients_list)
    except Exception as e:
        app.logger.error(f'Error in get_patients: {str(e)}')
        return jsonify({
            'error': _('Failed to fetch patients'),
            'details': str(e)
        }), 500
        app.logger.error(f'Traceback: {traceback.format_exc()}')
        return jsonify({
            'success': False,
            'error': 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วย',
            'details': str(e)
        }), 500

@app.route('/get_medicines')
def get_medicines():
    medicines = Medicine.query.all()
    medicines_list = [m.to_dict() for m in medicines]
    return jsonify(medicines_list)

@app.route('/add_medicine', methods=['POST'])
@login_required
@doctor_required
def add_medicine():
    data = request.json
    name = data.get('name', '').strip()
    custom_id = data.get('id', '').strip()

    if not name:
        return jsonify({'success': False, 'message': 'กรุณากรอกชื่อยา'}), 400
    
    if not custom_id:
        return jsonify({'success': False, 'message': 'กรุณากรอกรหัสยา'}), 400

    if Medicine.query.filter_by(name=name).first():
        return jsonify({'success': False, 'message': 'ชื่อยานี้มีอยู่แล้ว'}), 400
        
    if Medicine.query.get(custom_id):
        return jsonify({'success': False, 'message': 'รหัสยานี้มีอยู่แล้ว'}), 400

    new_medicine = Medicine(id=custom_id, name=name)
    db.session.add(new_medicine)
    db.session.commit()

    socketio.emit('medicine_update', {'action': 'add', 'medicine': new_medicine.to_dict()}, broadcast=True)
    return jsonify({'success': True, 'message': 'เพิ่มยาสำเร็จ'})

@app.route('/delete_medicine/<medicine_id>', methods=['POST'])
@login_required
@doctor_required
def delete_medicine(medicine_id):
    try:
        # Get the medicine
        medicine = Medicine.query.get(medicine_id)
        if not medicine:
            return jsonify({
                'success': False, 
                'message': 'ไม่พบยา'
            }), 404
        
        # Check if the medicine is being used in any prescriptions
        if Patient.query.filter_by(medicine_id=medicine_id).first():
            return jsonify({
                'success': False, 
                'message': 'ไม่สามารถลบยาได้ เนื่องจากมียานี้ถูกสั่งให้ผู้ป่วยแล้ว'
            }), 400
            
        # Delete the medicine
        db.session.delete(medicine)
        db.session.commit()
        
        print(f"Successfully deleted medicine with ID: {medicine_id}")
        
        # Emit socket.io event to update all clients
        socketio.emit('medicine_update', {
            'action': 'delete', 
            'medicine_id': medicine_id
        }, broadcast=True)
        
        return jsonify({
            'success': True, 
            'message': 'ลบยาสำเร็จ',
            'medicine_id': medicine_id
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting medicine {medicine_id}: {str(e)}")
        return jsonify({
            'success': False, 
            'message': f'เกิดข้อผิดพลาดในการลบยา: {str(e)}',
            'error': str(e),
            'type': type(e).__name__
        }), 500

from flask_socketio import emit

@app.route('/prescribe', methods=['POST'])
@login_required
@doctor_required
def prescribe():
    try:
        data = request.json
        patient = Patient.query.filter_by(id=data['patient_id']).first()
        medicine = Medicine.query.filter_by(id=data['medicine_id']).first()
        quantity = data.get('quantity', 1)  # Default to 1 if not provided

        if not patient or not medicine:
            return jsonify({'success': False, 'message': 'ไม่พบผู้ป่วยหรือยา'}), 404

        # Start a database transaction
        db.session.begin_nested()

        # Update patient record
        patient.medicine = f"{medicine.name} (จำนวน: {quantity})"
        patient.medicine_id = medicine.id
        patient.status = 'prescribed'  # Changed from 'done' to 'prescribed' to indicate prescription is ready
        patient.prescribed_time = datetime.utcnow()

        # Create QR code directory if it doesn't exist
        qr_code_dir = os.path.join(app.static_folder, 'qr_codes')
        os.makedirs(qr_code_dir, exist_ok=True)

        # Generate unique filename
        timestamp = int(time.time())
        filename = f"{patient.id}_{timestamp}.png"
        filepath = os.path.join(qr_code_dir, filename)


        # Create QR code data for medicine dispensing machine
        qr_data = {
            # Machine-readable format (keep it simple and consistent)
            'type': 'prescription',
            'pid': patient.id,  # Patient ID
            'mid': medicine.id,  # Medicine ID
            'qty': int(quantity),  # Quantity as integer
            'time': int(time.time()),  # Unix timestamp
            # Human-readable info (for verification)
            'pname': patient.name,
            'mname': medicine.name,
            'ptime': patient.prescribed_time.isoformat()
        }
        qr_data_str = json.dumps(qr_data, ensure_ascii=False)

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data_str)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filepath)
        
        # Update patient record with QR code path
        patient.qr_code = filename
        db.session.commit()

        # Get the updated patient data
        patient_data = {
            'id': patient.id,
            'name': patient.name,
            'symptoms': patient.symptoms,
            'status': patient.status,
            'medicine': patient.medicine,
            'medicine_id': patient.medicine_id,
            'prescribed_time': patient.prescribed_time.isoformat() if patient.prescribed_time else None,
            'qr_code': patient.qr_code,
            'created_at': patient.created_at.isoformat() if patient.created_at else None
        }

        # Prepare data to send to patient
        response_data = {
            'success': True,
            'patient_id': patient.id,
            'patient_name': patient.name,
            'medicine': f"{medicine.name} (จำนวน: {quantity})",
            'medicine_name': medicine.name,
            'quantity': quantity,
            'qr_code': qr_data_str,
            'qr_image_url': url_for('qr_code_file', filename=filename, _external=True),
            'qr_image_path': f"/static/qr_codes/{filename}",
            'prescribed_time': patient.prescribed_time.isoformat(),
            'status': 'prescribed',
            'timestamp': timestamp
        }

        # Notify the patient
        socketio.emit('prescription_ready', response_data, room=patient.id)
        app.logger.info(f'Sent prescription_ready to patient {patient.id}')
        
        # Also notify all doctors that the patient has been prescribed
        socketio.emit('patient_updated', {
            'patient_id': patient.id,
            'status': 'prescribed',
            'medicine': medicine.name,
            'medicine_quantity': quantity,
            'prescribed_time': patient.prescribed_time.isoformat(),
            'doctor_name': current_user.name
        }, namespace='/doctor')
        app.logger.info(f'Sent patient_updated to doctors_room')

        # Update the patient list for all doctors
        patients = Patient.query.order_by(Patient.created_at.desc()).all()
        patients_list = [{
            'id': p.id,
            'name': p.name,
            'symptoms': p.symptoms,
            'status': p.status or 'waiting',
            'medicine': p.medicine or '',
            'medicine_id': p.medicine_id or '',
            'prescribed_time': p.prescribed_time.isoformat() if p.prescribed_time else None,
            'created_at': p.created_at.isoformat() if p.created_at else None
        } for p in patients]
        
        socketio.emit('patients_updated', {
            'patients': patients_list
        }, namespace='/doctor')
        app.logger.info(f'Sent patients_updated to doctors_room with {len(patients_list)} patients')

        return jsonify(response_data)

    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error in prescribe: {str(e)}')
        app.logger.error(f'Traceback: {traceback.format_exc()}')
        return jsonify({
            'success': False,
            'error': 'เกิดข้อผิดพลาดในการสั่งยา',
            'details': str(e)
        }), 500
    finally:
        db.session.close()


@app.route('/qr_code/<filename>')
def qr_code_file(filename):
    """Serve QR code images from the static/qr_codes directory"""
    try:
        return send_from_directory('static/qr_codes', filename)
    except FileNotFoundError:
        return "QR code not found", 404

@app.route('/api/stats')
def get_stats():
    patients = Patient.query.all()
    medicines = Medicine.query.all()
    stats = {
        'waiting_patients': len([p for p in patients if p.status == 'waiting']),
        'completed_patients': len([p for p in patients if p.status == 'done']),
        'total_medicines': len(medicines),
        'online_patients': len(online_users['patients']),
        'online_doctors': len(online_users['doctors']),
        'chat_messages': ChatMessage.query.count()
    }
    return jsonify(stats)

@app.route('/api/patient/<int:patient_id>')
@login_required
def get_patient(patient_id):
    if current_user.role != 'doctor':
        return jsonify({'error': 'Unauthorized'}), 403
    
    patient = User.query.get_or_404(patient_id)
    return jsonify({
        'id': patient.id,
        'name': patient.name,
        'phone': patient.phone,
        'email': patient.email
        # Add any other fields you need
    })

def create_tables():
    """Create database tables."""
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            app.logger.info('Database tables created successfully')
            
            # Add initial data if needed
            # Example: Create admin user if not exists
            if not User.query.filter_by(username='admin').first():
                admin = User(
                    username='admin',
                    name='Administrator',
                    role='admin',
                    email='admin@example.com',
                    phone='0000000000',
                    password_hash=generate_password_hash('admin123')
                )
                db.session.add(admin)
                db.session.commit()
                app.logger.info('Created default admin user')
                
        except Exception as e:
            app.logger.error(f'Error creating database tables: {str(e)}')
            db.session.rollback()
            raise

# Create a URL processor to handle language prefixes
@app.url_defaults
def add_language_code(endpoint, values):
    # Skip if we're in a static file
    if endpoint == 'static':
        return
    
    # Get the current language from the session or default to 'en'
    lang = session.get('language', 'en')
    
    # Only add lang_code if it's not already in the URL and the endpoint we're building
    # is not 'set_language' itself. This ensures that even when we're inside the
    # `set_language` view (e.g. in the exception handler) any generated URLs will still
    # get a language code injected correctly.
    if 'lang_code' not in values and endpoint != 'set_language':
        values['lang_code'] = lang

@app.url_value_preprocessor
def pull_lang_code(endpoint, values):
    if values is None:
        values = {}
    
    # Get the language from the URL or default to 'en'
    lang = values.pop('lang_code', 'en')
    
if __name__ == '__main__':
    try:
        # Create database tables if they don't exist
        create_tables()
        
        # Ensure upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Start the application
        app.logger.info('Starting application...')
        port = int(os.environ.get('PORT', 5001))
        host = os.environ.get('HOST', '0.0.0.0')
        
        print(f"Starting server on http://{host}:{port}")
        print(f" * Running on http://{host}:{port} (Press CTRL+C to quit)")
        
        # Run the application with Socket.IO in HTTP mode
        socketio.run(
            app,
            host=host,
            port=port,
            debug=True,
            use_reloader=True,
            log_output=True
        )
        
    except Exception as e:
        app.logger.error(f'Failed to start application: {str(e)}')
        import traceback
        traceback.print_exc()
        sys.exit(1)