from flask import (
    Flask, request, redirect, render_template,
    jsonify, session, url_for, send_from_directory, render_template_string
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import mysql.connector
from mysql.connector import Error
from pathlib import Path
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
import requests
from urllib.parse import quote_plus

app = Flask(__name__)

# ----------------------
# Configuration
# ----------------------

# Configure Secret Key for Session
app.config['SECRET_KEY'] = 'your_secure_random_secret_key'  # Replace with a strong secret key
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = Path('./flask_session')
app.config['SESSION_PERMANENT'] = False

# Initialize Extensions
Session(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# ----------------------
# Logging Configuration
# ----------------------

# Ensure log directory exists using pathlib
log_dir = Path('logs')
log_dir.mkdir(exist_ok=True)

logger = logging.getLogger('main_app')
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')

# File handler for all logs
file_handler = RotatingFileHandler(
    'logs/app.log',
    maxBytes=1024 * 1024,  # 1MB
    backupCount=5
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

# File handler for errors
error_handler = RotatingFileHandler(
    'logs/backend.log',
    maxBytes=1024 * 1024,
    backupCount=5
)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(formatter)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(error_handler)
logger.addHandler(console_handler)

# ----------------------
# Database Configuration for XAMPP
# ----------------------

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",  # XAMPP MySQL default has no password
    "database": "zoho_oauth_db",
    "port": 3306
}

# Function to create database and tables if they don't exist
def init_database():
    try:
        conn = mysql.connector.connect(
            host=DB_CONFIG["host"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            port=DB_CONFIG["port"]
        )
        cursor = conn.cursor()

        # Create database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        cursor.execute(f"USE {DB_CONFIG['database']}")

        # Create signup table
        cursor.execute(""" 
            CREATE TABLE IF NOT EXISTS signup ( 
                id INT AUTO_INCREMENT PRIMARY KEY, 
                email VARCHAR(255) UNIQUE NOT NULL, 
                password VARCHAR(255) NOT NULL, 
                first_name VARCHAR(255), 
                last_name VARCHAR(255), 
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
            ) 
        """)

        # Create signin table
        cursor.execute(""" 
            CREATE TABLE IF NOT EXISTS signin ( 
                id INT AUTO_INCREMENT PRIMARY KEY, 
                email VARCHAR(255) UNIQUE NOT NULL, 
                password VARCHAR(255) NOT NULL, 
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
            ) 
        """)

        # Create applications table
        cursor.execute(""" 
            CREATE TABLE IF NOT EXISTS applications ( 
                id INT AUTO_INCREMENT PRIMARY KEY, 
                name VARCHAR(255) NOT NULL 
            ) 
        """)

        # Create scopes table
        cursor.execute(""" 
            CREATE TABLE IF NOT EXISTS scopes ( 
                id INT AUTO_INCREMENT PRIMARY KEY, 
                application_id INT NOT NULL, 
                scope_name VARCHAR(255) NOT NULL, 
                FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE 
            ) 
        """)

        conn.commit()
        logger.info("Database and tables initialized successfully")

    except Error as e:
        logger.error(f"Database initialization error: {e}")
        raise
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# Initialize database on startup
init_database()

# Function to get database connection
def get_db_connection():
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        logger.error(f"Error connecting to database: {e}")
        raise

# ----------------------
# OAuth Configuration
# ----------------------

# Define Zoho OAuth domains based on region
ZOHO_DOMAINS = {
    'US': 'https://accounts.zoho.com',
    'AU': 'https://accounts.zoho.com.au',
    'EU': 'https://accounts.zoho.eu',
    'IN': 'https://accounts.zoho.in',
    'CN': 'https://accounts.zoho.com.cn',
    'JP': 'https://accounts.zoho.jp',
    'SA': 'https://accounts.zoho.sa',
    'CA': 'https://accounts.zohocloud.ca'
}

RESPONSE_TYPE = 'code'
GRANT_TYPE = 'authorization_code'
REDIRECT_URI_DEFAULT = 'http://127.0.0.1:8000/oauth_redirect/'

# In-memory storage for OAuth sessions
oauth_sessions = {}

# ----------------------
# Templates
# ----------------------

# Inline HTML templates for OAuth success and error messages
ERROR_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Error</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f8d7da; color: #721c24; text-align: center; padding-top: 50px; }
        .container { display: inline-block; padding: 20px; border: 1px solid #f5c6cb; border-radius: 5px; background-color: #f8d7da; }
        h1 { margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Error</h1>
        <p>{{ message }}</p>
    </div>
</body>
</html>
"""

SUCCESS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OAuth Success</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #d4edda; color: #155724; text-align: center; padding-top: 50px; }
        .container { display: inline-block; padding: 20px; border: 1px solid #c3e6cb; border-radius: 5px; background-color: #d4edda; }
        h1 { margin-bottom: 10px; }
        pre { text-align: left; display: inline-block; background-color: #e2e3e5; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OAuth Successful</h1>
        <p>Access Token:</p>
        <pre>{{ access_token }}</pre>
        <p>Refresh Token:</p>
        <pre>{{ refresh_token }}</pre>
    </div>
</body>
</html>
"""

# ----------------------
# Route Handlers
# ----------------------

@app.route('/')
def index():
    return redirect('/signin')

@app.route('/signin')
def signin():
    return render_template('Signin_up/signin.html')

@app.route('/signup')
def signup():
    return render_template('Signin_up/signin.html')

@app.route('/auth', methods=['POST'])
@limiter.limit("10 per minute")
def auth():
    try:
        # Extract form data
        action = request.form.get('action')
        email = request.form.get('email').strip()
        password = request.form.get('password').strip()

        # Initialize error message
        error = None

        # Basic validation
        if not email or not password:
            error = "Email and password are required."

        if not is_valid_email(email):
            error = "Invalid email format."

        if action == 'signup':
            first_name = request.form.get('first_name').strip()
            last_name = request.form.get('last_name').strip()
            confirm_password = request.form.get('confirm_password').strip()

            # Additional validations for sign-up
            if not first_name or not last_name:
                error = "First name and last name are required for sign-up."

            if password != confirm_password:
                error = "Passwords do not match."

            if len(password) < 6:
                error = "Password must be at least 6 characters long."

        # If there's any error, redirect back with error message
        if error:
            logger.warning(f"Authentication error: {error}")
            return render_template('Signin_up/signin.html', error=error)

        # Database operations
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        if action == 'signup':
            first_name = request.form.get('first_name').strip()
            last_name = request.form.get('last_name').strip()
            confirm_password = request.form.get('confirm_password').strip()

            # Check if user already exists in signup table
            cursor.execute("SELECT id FROM signup WHERE email = %s", (email,))
            if cursor.fetchone():
                error = "Email is already registered."
                logger.warning(f"Sign-Up attempt with existing email: {email}")
                return render_template('Signin_up/signin.html', error=error)

            # Hash the password
            hashed_password = generate_password_hash(password)

            # Insert into signup table
            cursor.execute("""
                INSERT INTO signup (email, password, first_name, last_name)
                VALUES (%s, %s, %s, %s)
            """, (email, hashed_password, first_name, last_name))

            # Insert into signin table
            cursor.execute("""
                INSERT INTO signin (email, password)
                VALUES (%s, %s)
            """, (email, hashed_password))

            conn.commit()
            logger.info(f"New user signed up: {email}")

            message = "Sign-Up successful! Please sign in with your credentials."
            return render_template('Signin_up/signin.html', message=message)

        elif action == 'signin':
            # Check if user exists in signin table
            cursor.execute("SELECT * FROM signin WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                # Authentication successful
                session['user_id'] = user['id']
                session['email'] = user['email']
                logger.info(f"User signed in: {email}")
                return redirect('/connector')
            else:
                error = "Invalid email or password."
                logger.warning(f"Failed sign-in attempt for email: {email}")
                return render_template('Signin_up/signin.html', error=error)

        else:
            error = "Invalid action."
            logger.error(f"Invalid action received: {action}")
            return render_template('Signin_up/signin.html', error=error)

    except Error as e:
        logger.error(f"Database error during authentication: {e}")
        return render_template('Signin_up/signin.html', error="Internal server error."), 500

    except Exception as e:
        logger.error(f"Error during authentication: {e}")
        return render_template('Signin_up/signin.html', error="An unexpected error occurred."), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals() and conn.is_connected():
            conn.close()

@app.route('/get_oauth_tokens', methods=['POST'])
def start_oauth():
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    redirect_url = request.form.get('redirect_url', REDIRECT_URI_DEFAULT)
    scopes_raw = request.form.get('scopes', '')  # Capture scopes
    region = request.form.get('region')

    logger.debug(
        f"Received POST data - client_id: {client_id}, "
        f"client_secret: {'***' if client_secret else None}, "
        f"redirect_url: {redirect_url}, scopes: {scopes_raw}, region: {region}"
    )

    # Validate required fields (client_id, client_secret, region)
    if not all([client_id, client_secret, region]):
        return render_template_string(ERROR_TEMPLATE, 
            message="Client ID, Client Secret, and Region are required."
        ), 400

    # Handle optional scopes
    scopes_str = ""
    if scopes_raw:
        requested_scopes = [s.strip() for s in scopes_raw.split(',') if s.strip()]
        if len(requested_scopes) > 50:
            return render_template_string(ERROR_TEMPLATE,
                message="Too many scopes requested. Maximum is 50 at once."
            ), 400

        scopes_str = " ".join(requested_scopes)
        if 'offline_access' not in requested_scopes:
            scopes_str += ' offline_access'

    else:
        # If no scopes are provided, default to 'offline_access'
        scopes_str = 'offline_access'

    # Generate state and store session
    state = str(uuid.uuid4())
    oauth_sessions[state] = {
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_url': redirect_url,
        'region': region,
        'scopes': scopes_str
    }

    # Build the authorization URL
    auth_url = (
        f"{ZOHO_DOMAINS[region]}/oauth/v2/auth?"
        f"response_type={RESPONSE_TYPE}&"
        f"client_id={client_id}&"
        f"redirect_uri={quote_plus(redirect_url)}&"
        f"access_type=offline&"
        f"prompt=consent&"
        f"state={state}"
    )

    if scopes_str:
        auth_url += f"&scope={quote_plus(scopes_str)}"

    logger.info(f"Redirecting to Zoho OAuth URL: {auth_url}")
    return redirect(auth_url)



@app.route('/oauth_redirect/', methods=['GET'])
def oauth_redirect():
    code = request.args.get('code')
    state_received = request.args.get('state')

    logger.debug(f"Received OAuth Redirect with code: {code} and state: {state_received}")

    if not code:
        return render_template_string(ERROR_TEMPLATE, 
            message="Authorization code not found."
        ), 400

    session_data = oauth_sessions.get(state_received)
    if not session_data:
        return render_template_string(ERROR_TEMPLATE,
            message="Invalid or expired state parameter."
        ), 400

    client_id = session_data.get('client_id')
    client_secret = session_data.get('client_secret')
    redirect_uri = session_data.get('redirect_url')
    region = session_data.get('region')

    if not all([client_id, client_secret, redirect_uri, region]):
        return render_template_string(ERROR_TEMPLATE,
            message="Missing OAuth credentials in session. Please try again."
        ), 400

    token_url = f"{ZOHO_DOMAINS[region]}/oauth/v2/token"
    
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": GRANT_TYPE,
        "code": code
    }
    
    try:
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        token_data = response.json()
        
        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')
        
        if not access_token or not refresh_token:
            logger.error("Failed to retrieve tokens from Zoho.")
            return render_template_string(ERROR_TEMPLATE,
                message="Failed to generate tokens. Please check the logs."
            ), 400
            
        # Optionally, store tokens in the database associated with the user or application
        # This implementation just displays them

        del oauth_sessions[state_received]
        
        return render_template_string(SUCCESS_TEMPLATE,
            access_token=access_token,
            refresh_token=refresh_token
        )
        
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred while fetching tokens: {http_err}")
        return render_template_string(ERROR_TEMPLATE,
            message="HTTP error occurred while fetching tokens. Please check the logs."
        ), 400
    except Exception as e:
        logger.error(f"Error generating tokens: {e}")
        return render_template_string(ERROR_TEMPLATE,
            message="Failed to generate tokens. Please check the logs."
        ), 400

# ----------------------
# API Routes
# ----------------------

@app.route('/api/applications')
def get_applications():
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, name FROM applications")
        applications = cursor.fetchall()
        return jsonify({"applications": applications})
    except Error as e:
        logger.error(f"Database error in get_applications: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'connection' in locals() and connection:
            connection.close()

@app.route('/api/scopes')
def get_scopes():
    application_id = request.args.get('application_id')
    
    if not application_id:
        return jsonify({"error": "Missing 'application_id' parameter"}), 400
    
    if not application_id.isdigit():
        return jsonify({"error": "'application_id' must be an integer"}), 400
    
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        query = "SELECT scope_name FROM scopes WHERE application_id = %s"
        cursor.execute(query, (int(application_id),))
        scopes = [row['scope_name'] for row in cursor.fetchall()]
        return jsonify({"scopes": scopes})
    except Error as e:
        logger.error(f"Database error in get_scopes: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'connection' in locals() and connection:
            connection.close()

# ----------------------
# Error Handlers
# ----------------------

@app.errorhandler(404)
def not_found_error(error):
    return render_template('connector/connector.html', error="Page not found."), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return render_template('connector/connector.html', error="Internal server error."), 500

# ----------------------
# Static Files Serving
# ----------------------

# Serve CSS and JS files from /Templates/Signin_up/
@app.route('/Templates/Signin_up/<path:filename>')
def serve_signin_css_js(filename):
    return send_from_directory('Templates/Signin_up', filename)

# Serve CSS and JS files from /Templates/connector/
@app.route('/Templates/connector/<path:filename>')
def serve_connector_css_js(filename):
    return send_from_directory('Templates/connector', filename)

# ----------------------
# Utility Functions
# ----------------------

def is_valid_email(email):
    import re
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    return re.match(regex, email)

# ----------------------
# Ensure Directories Exist
# ----------------------

def ensure_directories():
    Path('./flask_session').mkdir(exist_ok=True)
    Path('./logs').mkdir(exist_ok=True)

# Initialize directories on startup
ensure_directories()

if __name__ == '__main__':
    app.run(debug=True, port=8000)
