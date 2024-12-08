from urllib.parse import urlencode
import pandas as pd
import random
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import spacy
from sentence_transformers import SentenceTransformer
from datetime import datetime
from nltk.corpus import wordnet
import json
import firebase_admin
from firebase_admin import auth, credentials
from flask import Flask, request, jsonify, session, redirect, url_for, render_template, flash
from google.auth.transport.requests import Request
from google.oauth2.service_account import Credentials
import requests

# Initialize Flask app
app = Flask(__name__)

# Basic configuration
app.config.update({
    'SECRET_KEY': os.environ.get('FLASK_SECRET_KEY', os.urandom(24)),
    'SQLALCHEMY_DATABASE_URI': os.environ.get('DATABASE_URI', 'sqlite:///app.db'),
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'GOOGLE_CLIENT_ID': os.environ.get('GOOGLE_CLIENT_ID'),
    'GOOGLE_CLIENT_SECRET': os.environ.get('GOOGLE_CLIENT_SECRET'),
    'FIREBASE_CLIENT_ID': os.environ.get('FIREBASE_CLIENT_ID'),
    'BASE_URL': os.environ.get('BASE_URL', 'https://sanjeevanigpt.onrender.com')
})

# Define redirect URI after app configuration
REDIRECT_URI = f"{app.config['BASE_URL']}/callback"

# Initialize Firebase Admin SDK with explicit options
cred = credentials.Certificate('./sanjeevani-gpt-firebase-adminsdk-17223-27ceb5f6db.json')
firebase_admin.initialize_app(cred, {
    'authDomain': 'sanjeevani-gpt.firebaseapp.com',
})

# Your Firebase project's Web Client ID
CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')

# Constants for OAuth
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
SCOPE = "openid email profile"

# Extensions Initialization
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
nlp = spacy.load('en_core_web_sm')
sentence_model = SentenceTransformer('all-MiniLM-L6-v2')


# User model for authentication
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


# Greeting model for time-based responses
class Greeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time_of_day = db.Column(db.String(50), nullable=False)
    greeting_text = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(50), nullable=False)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.String(100), nullable=False)
    messages = db.Column(db.Text, nullable=False)  # Store JSON or plain text of messages

    user = db.relationship('User', backref='conversations')


# Load FAQ data from CSV
faq_data = pd.read_csv('Data.csv')

# Service Account Key Path
SERVICE_ACCOUNT_FILE = "./sanjeevani-gpt-firebase-adminsdk-17223-27ceb5f6db.json"
SCOPES = ['https://www.googleapis.com/auth/cloud-platform']


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Function to generate Access Token
def get_access_token():
    credentials = Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES
    )
    credentials.refresh(Request())
    return credentials.token


# Define keyword extraction and synonym functions
def get_synonyms(word):
    synonyms = set()
    for syn in wordnet.synsets(word):
        for lemma in syn.lemmas():
            synonyms.add(lemma.name())
    return synonyms


def extract_keywords(user_input):
    doc = nlp(user_input)
    keywords = set()
    for token in doc:
        if token.is_alpha and not token.is_stop:
            keywords.add(token.lemma_)
            keywords.update(get_synonyms(token.text))
    return keywords


def get_coping_method(user_input, context=None):
    keywords = extract_keywords(user_input)
    if context:
        keywords.update(extract_keywords(context))  # Combine with previous context

    for index, row in faq_data.iterrows():
        situation = row['Scenario'].lower()
        if any(keyword in situation for keyword in keywords):
            coping_methods = row['Method'].split('|')
            references = row['Reference'].split('|')
            if len(coping_methods) == len(references):
                selected_method = random.choice(coping_methods)
                selected_index = coping_methods.index(selected_method)
                selected_reference = references[selected_index]
                return selected_method, selected_reference
    return "I'm still trying to understand your concern. Could you clarify further?", None


def get_greeting(user_type='general'):
    current_hour = datetime.now().hour
    time_of_day = (
        'morning' if 5 <= current_hour < 12 else
        'afternoon' if 12 <= current_hour < 17 else
        'evening' if 17 <= current_hour < 21 else
        'night'
    )
    greeting = Greeting.query.filter_by(time_of_day=time_of_day, user_type=user_type).order_by(db.func.random()).first()
    return greeting.greeting_text if greeting else "Hello!"


def handle_follow_up(previous_context, current_message):
    prev_keywords = extract_keywords(previous_context)
    curr_keywords = extract_keywords(current_message)

    if any(keyword in prev_keywords for keyword in curr_keywords):
        return "It seems you're asking more about your previous concern. Let me provide additional details..."
    else:
        return handle_message(current_message)


def is_related_to_previous(previous_message, current_message):
    prev_keywords = extract_keywords(previous_message)
    curr_keywords = extract_keywords(current_message)
    return any(keyword in prev_keywords for keyword in curr_keywords)


# Flask routes
@app.route('/')
def index():
    return render_template('index.html', is_authenticated=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Add authorized domains to the template context
        authorized_domains = [
            'localhost',
            '127.0.0.1',
            'localhost:5001',
            'sanjeevani-gpt.firebaseapp.com'
        ]
        return render_template('login.html', authorized_domains=authorized_domains)
    
    if 'id_token' in request.args:
        return firebase_login()
        
    username = request.form.get('username')
    password = request.form.get('password')
    
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for('profile'))
    else:
        flash('Invalid credentials')
        return redirect(url_for('login'))


@app.route('/callback')
def callback():
    id_token = request.args.get('id_token')
    if not id_token:
        return "Missing ID Token", 400

    try:
        decoded_token = auth.verify_id_token(id_token)
        user_id = decoded_token['uid']
        return f"User authenticated: {user_id}"
    except Exception as e:
        return f"Error verifying ID token: {str(e)}", 400


@app.route('/firebase_login', methods=['GET', 'POST'])
def firebase_login():
    if request.method == 'POST':
        data = request.get_json()
        id_token = data.get('id_token')
    else:
        id_token = request.args.get('id_token')

    if not id_token:
        return jsonify({"error": "Missing ID token"}), 400

    try:
        # Verify the ID token
        decoded_token = auth.verify_id_token(id_token)
        
        # Get user info
        user_email = decoded_token.get('email')
        user_name = decoded_token.get('name', user_email.split('@')[0])
        
        # Check if user exists in your database
        user = User.query.filter_by(username=user_email).first()
        
        if not user:
            # Create new user if they don't exist
            user = User(
                username=user_email,
                password=generate_password_hash(os.urandom(24).hex())
            )
            db.session.add(user)
            db.session.commit()

        # Log the user in
        login_user(user)
        
        # Store additional user info in session
        session['user_email'] = user_email
        session['user_name'] = user_name
        
        if request.method == 'POST':
            return jsonify({"success": True, "redirect": url_for('profile')})
        return redirect(url_for('profile'))

    except Exception as e:
        error_message = str(e)
        print(f"Authentication error: {error_message}")  # For debugging
        if request.method == 'POST':
            return jsonify({"error": error_message}), 400
        return f"Authentication failed: {error_message}", 400


@app.route('/glogin')
def glogin():
    google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    redirect_uri = "https://sanjeevani-gpt.firebaseapp.com/__/auth/handler"

    # Generate a secure random state parameter
    state = os.urandom(16).hex()  # Secure random state
    session['oauth_state'] = state  # Store state in session for validation later

    params = {
        "client_id": app.config["GOOGLE_CLIENT_ID"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state  # Include state parameter
    }
    return redirect(f"{google_auth_url}?{urlencode(params)}")


# Firebase Authentication Handler
@app.route('/__/auth/handler')
def auth_handler():
    # Retrieve the state from the request
    request_state = request.args.get('state')
    session_state = session.get('oauth_state')  # Retrieve the stored state from the session

    if not request_state or request_state != session_state:
        return "Invalid or missing state parameter. CSRF validation failed.", 400

    # Continue with token exchange
    authorization_code = request.args.get('code')
    if not authorization_code:
        return "Authorization code missing", 400

    # Exchange code for tokens
    token_endpoint = "https://oauth2.googleapis.com/token"
    payload = {
        "code": authorization_code,
        "client_id": app.config["GOOGLE_CLIENT_ID"],
        "client_secret": app.config["GOOGLE_CLIENT_SECRET"],
        "redirect_uri": "https://sanjeevani-gpt.firebaseapp.com/__/auth/handler",
        "grant_type": "authorization_code",
    }

    token_response = requests.post(token_endpoint, data=payload)
    if not token_response.ok:
        return f"Token exchange failed: {token_response.text}", 400

    tokens = token_response.json()
    id_token = tokens.get("id_token")

    # Verify and process the ID token
    try:
        decoded_token = auth.verify_id_token(id_token)
    except ValueError as e:
        return f"Invalid ID token: {str(e)}", 400

    user_email = decoded_token["email"]
    user_name = decoded_token.get("name")

    # Authentication logic
    session["user"] = {"email": user_email, "name": user_name}
    return f"Successfully authenticated as: {user_email}"


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    username = request.form['username']
    password = request.form['password']

    # Check if username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already exists, please choose a different one.')
        return redirect(url_for('register'))

    # Create and save the new user
    new_user = User(username=username, password=generate_password_hash(password))
    db.session.add(new_user)
    db.session.commit()
    flash('Registration successful! You can now log in.')
    return redirect(url_for('login'))


@app.route('/profile')
@login_required
def profile():
    try:
        # Get username from current_user, fallback to email from session
        username = current_user.username
        # If username is an email, show only the part before @
        if '@' in username:
            username = username.split('@')[0]
        
        return render_template('profile.html', 
                             username=username,
                             user_email=session.get('user_email'),
                             user_name=session.get('user_name'))
    except Exception as e:
        print(f"Profile error: {str(e)}")  # For debugging
        return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# Temporary storage for unauthenticated user conversations (global dictionary)
unauthenticated_conversations = {}


@socketio.on('message')
def handle_message(msg):
    print('Received message: ' + msg)

    # Define follow-up phrases
    follow_up_phrases = {
        "tell me more", "what else", "go on", "continue", "expand on that", "can you elaborate", "explain it further",
        "more", "more ways", "more methods", "more techniques"
    }

    # Detect if the input is a greeting
    greeting_phrases = {
        'hello', 'hi', 'hey', 'good morning', 'good afternoon', 'good evening', 'greetings'
    }
    is_greeting = (
            msg.lower() in greeting_phrases or
            any(msg.lower().startswith(phrase) for phrase in greeting_phrases)
    )

    # Determine user type for personalized greetings
    user_type = (
        'VIP' if current_user.is_authenticated and getattr(current_user, 'role', '') in ['VIP', 'Admin']
        else 'returning_user' if current_user.is_authenticated
        else 'new_user'
    )

    if is_greeting:
        greeting_text = get_greeting(user_type=user_type)
        emit('response', greeting_text)
        return

    # Handle contextual conversations
    if current_user.is_authenticated:
        # Fetch or create conversation for authenticated users
        conversation = Conversation.query.filter_by(user_id=current_user.id).order_by(Conversation.id.desc()).first()
        if not conversation:
            conversation = Conversation(user_id=current_user.id, date=str(datetime.now()), messages="[]")
            db.session.add(conversation)
            db.session.commit()

        # Retrieve and update conversation history
        messages = json.loads(conversation.messages)
    else:
        # Handle unauthenticated users with temporary in-memory storage
        user_ip = request.remote_addr
        if user_ip not in unauthenticated_conversations:
            unauthenticated_conversations[user_ip] = []

        messages = unauthenticated_conversations[user_ip]

    # Add the user's message to the conversation history
    messages.append({"role": "user", "content": msg})

    # Detect if the input is a follow-up
    is_follow_up = (
            msg.lower() in follow_up_phrases or  # Matches generic follow-up phrases
            (len(messages) > 1 and is_related_to_previous(messages[-2]["content"], msg))
    # Contextually related to previous message
    )

    if is_follow_up:
        previous_context = messages[-2]["content"]  # Get the previous message context
        method, reference = get_coping_method(msg, context=previous_context)
    else:
        method, reference = get_coping_method(msg)

    # Construct the response
    if reference is None:
        answer = f"{method}"
    else:
        answer = f"""{method} 

Reference: {reference}"""

    # Save the assistant's response in the conversation history
    messages.append({"role": "assistant", "content": answer})

    if current_user.is_authenticated:
        # Update the database for authenticated users
        conversation.messages = json.dumps(messages)
        db.session.commit()
    else:
        # Update temporary storage for unauthenticated users
        unauthenticated_conversations[user_ip] = messages

    # Emit the response
    emit('response', answer)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, 
                 host='localhost',  # Explicitly set host
                 port=5001,         # Match the port in your configuration
                 allow_unsafe_werkzeug=True, 
                 debug=True)
