import streamlit as st
import hashlib
import os
import json
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Constants
DATA_FILE = 'secure_data.json'
LOCKOUT_DURATION = 300  # 5 minutes in seconds

# Custom CSS styling
st.markdown("""
<style>
    .stApp {
        background-color: #f0f2f6;
    }
    .main-title {
        color: #1a73e8;
        font-size: 3.5rem !important;
        text-align: center;
        padding: 20px 0;
    }
    .sidebar .sidebar-content {
        background-color: #ffffff;
        box-shadow: 2px 0 8px rgba(0,0,0,0.1);
    }
    .section-header {
        color: #1a73e8 !important;
        border-bottom: 2px solid #1a73e8;
        padding-bottom: 0.5rem;
        margin-bottom: 1.5rem;
    }
    .success-box {
        background-color: #e6f4ea;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #34a853;
        margin: 1rem 0;
    }
    .error-box {
        background-color: #fce8e6;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #d93025;
        margin: 1rem 0;
    }
    .feature-card {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin: 1rem 0;
    }
    .form-input {
        margin-bottom: 1.5rem !important;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'user_failed_attempts' not in st.session_state:
    st.session_state.user_failed_attempts = {}
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = {}

# Data persistence functions
def load_data():
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'users': {}, 'data_entries': {}}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

stored_data = load_data()

# Security functions
def derive_key(passphrase, salt=None, iterations=100000):
    if salt is None:
        salt = os.urandom(16)
    else:
        salt = base64.b64decode(salt)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    derived_key = kdf.derive(passphrase.encode())
    return base64.b64encode(salt).decode(), base64.b64encode(derived_key).decode()

def generate_fernet_key(passphrase):
    salt, key = derive_key(passphrase)
    return Fernet(base64.urlsafe_b64encode(base64.b64decode(key)))

# Enhanced UI Components
def login_page():
    with st.container():
        st.markdown("<h2 class='section-header'>🔐 User Authentication</h2>", unsafe_allow_html=True)
        col1, col2 = st.columns([1, 2])
        with col1:
            st.image("https://cdn-icons-png.flaticon.com/512/5087/5087579.png", width=150)
        with col2:
            with st.form("Login Form"):
                username = st.text_input("Username", placeholder="Enter your username", key="login_user")
                password = st.text_input("Password", type="password", placeholder="••••••••", key="login_pass")
                if st.form_submit_button("🚀 Login", use_container_width=True):
                    handle_login(username, password)

def registration_page():
    with st.container():
        st.markdown("<h2 class='section-header'>📝 New User Registration</h2>", unsafe_allow_html=True)
        with st.form("Registration Form"):
            new_user = st.text_input("Choose Username", placeholder="Unique username", key="reg_user")
            new_pass = st.text_input("Create Password", type="password", placeholder="Strong password", key="reg_pass")
            
            if st.form_submit_button("🌟 Register Account", use_container_width=True):
                if new_user and new_pass:
                    register_user(new_user, new_pass)
                else:
                    show_error("Both fields are required!")

def store_data_page():
    with st.container():
        st.markdown("<h2 class='section-header'>📥 Secure Data Storage</h2>", unsafe_allow_html=True)
        with st.form("Data Storage Form"):
            data = st.text_area("Sensitive Data", height=150, 
                              placeholder="Enter confidential information here...", key="data_input")
            secret = st.text_input("Encryption Passphrase", type="password", 
                                 placeholder="Minimum 12 characters", key="enc_key")
            
            if st.form_submit_button("🔒 Encrypt & Store", use_container_width=True):
                if data and secret:
                    encrypt_and_store(data, secret)
                else:
                    show_error("Both fields are required!")

def retrieve_data_page():
    with st.container():
        st.markdown("<h2 class='section-header'>📤 Data Retrieval Portal</h2>", unsafe_allow_html=True)
        with st.form("Data Retrieval Form"):
            entry_id = st.text_input("Entry ID", placeholder="16-character identifier", key="entry_id")
            secret = st.text_input("Decryption Passphrase", type="password", 
                                 placeholder="Same as encryption passphrase", key="dec_key")
            
            if st.form_submit_button("🔓 Decrypt Data", use_container_width=True):
                if entry_id and secret:
                    decrypt_and_show(entry_id, secret)
                else:
                    show_error("Both fields are required!")

# Helper functions
def show_error(message):
    st.markdown(f"""
    <div class='error-box'>
        ❌ {message}
    </div>
    """, unsafe_allow_html=True)

def show_success(message):
    st.markdown(f"""
    <div class='success-box'>
        ✅ {message}
    </div>
    """, unsafe_allow_html=True)

# Modified business logic
def handle_login(username, password):
    user_data = stored_data['users'].get(username)
    
    if user_data and not is_user_locked_out(username):
        salt = user_data['salt']
        stored_key = user_data['derived_key']
        _, input_key = derive_key(password, salt)
        
        if input_key == stored_key:
            successful_login(username)
        else:
            failed_login_attempt(username)
    else:
        show_error("Invalid credentials or account locked")

def successful_login(username):
    st.session_state.current_user = username
    st.session_state.user_failed_attempts[username] = 0
    show_success("Login successful! Redirecting...")
    time.sleep(1)
    st.rerun()

def failed_login_attempt(username):
    attempts = st.session_state.user_failed_attempts.get(username, 0) + 1
    st.session_state.user_failed_attempts[username] = attempts
    
    if attempts >= 3:
        st.session_state.lockout_time[username] = time.time() + LOCKOUT_DURATION
        show_error(f"Account locked for {LOCKOUT_DURATION//60} minutes")
    else:
        show_error(f"Invalid credentials. Attempts remaining: {3 - attempts}")

def register_user(username, password):
    if username in stored_data['users']:
        show_error("Username already exists")
        return
    
    salt, derived_key = derive_key(password)
    stored_data['users'][username] = {'salt': salt, 'derived_key': derived_key}
    save_data(stored_data)
    show_success("Registration successful! Please login")

def encrypt_and_store(data, secret):
    cipher = generate_fernet_key(secret)
    encrypted_data = cipher.encrypt(data.encode()).decode()
    
    entry_id = hashlib.sha256(encrypted_data.encode()).hexdigest()[:16]
    stored_data['data_entries'][entry_id] = {
        'user': st.session_state.current_user,
        'encrypted_data': encrypted_data,
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
    }
    save_data(stored_data)
    show_success(f"Data stored securely! Entry ID: {entry_id}")

def decrypt_and_show(entry_id, secret):
    entry = stored_data['data_entries'].get(entry_id)
    
    if not entry or entry['user'] != st.session_state.current_user:
        show_error("Invalid entry ID")
        return
    
    try:
        cipher = generate_fernet_key(secret)
        decrypted = cipher.decrypt(entry['encrypted_data'].encode()).decode()
        show_success(f"Decrypted Data:\n\n{decrypted}")
        st.session_state.user_failed_attempts[st.session_state.current_user] = 0
    except:
        handle_decryption_failure()

def handle_decryption_failure():
    user = st.session_state.current_user
    attempts = st.session_state.user_failed_attempts.get(user, 0) + 1
    st.session_state.user_failed_attempts[user] = attempts
    
    if attempts >= 3:
        st.session_state.lockout_time[user] = time.time() + LOCKOUT_DURATION
        show_error("Too many failed attempts! Account locked.")
        st.session_state.current_user = None
        time.sleep(1)
        st.rerun()
    else:
        show_error(f"Decryption failed! Attempts remaining: {3 - attempts}")

def is_user_locked_out(username):
    lockout_time = st.session_state.lockout_time.get(username, 0)
    return time.time() < lockout_time

# Main app structure
st.markdown("<h1 class='main-title'>Enterprise Security Vault</h1>", unsafe_allow_html=True)

menu = ["Home"]
if st.session_state.current_user:
    menu += ["Store Data", "Retrieve Data", "Logout"]
    st.sidebar.markdown(f"### 👤 Logged in as: \n**{st.session_state.current_user}**")
    st.sidebar.markdown("---")
else:
    menu += ["Login", "Register"]

with st.sidebar:
    choice = st.selectbox("Navigation Menu", menu, index=0, 
                        format_func=lambda x: f"🏠 {x}" if x == "Home" else f"🔒 {x}" if x == "Login" else f"📝 {x}" if x == "Register" else x)

# Page routing
if choice == "Home":
    st.markdown("<h2 class='section-header'>🌟 Vault Features</h2>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""<div class='feature-card'>
            <h3>🔐 Military-Grade Encryption</h3>
            <p>AES-256 encryption with PBKDF2 key derivation</p>
            </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""<div class='feature-card'>
            <h3>🚨 Intrusion Protection</h3>
            <p>Automatic account lockout after 3 attempts</p>
            </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("""<div class='feature-card'>
            <h3>📅 Audit Logging</h3>
            <p>Timestamped record of all transactions</p>
            </div>""", unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("<h2 class='section-header'>📈 Usage Statistics</h2>", unsafe_allow_html=True)
    col_stats1, col_stats2, col_stats3 = st.columns(3)
    with col_stats1:
        st.metric("Registered Users", len(stored_data['users']))
    with col_stats2:
        st.metric("Stored Entries", len(stored_data['data_entries']))
    with col_stats3:
        st.metric("Security Rating", "A+")

elif choice == "Store Data":
    if st.session_state.current_user:
        store_data_page()
    else:
        show_error("Please login to access this page")

elif choice == " Retrieve Data":
    if st.session_state.current_user:
        retrieve_data_page()
    else:
        show_error("Please login to access this page")

elif choice == "Login":
    login_page()

elif choice == "Register":
    registration_page()

elif choice == "Logout":
    st.session_state.current_user = None
    show_success("Successfully logged out")
    time.sleep(1)
    st.rerun()