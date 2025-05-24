# banking_app.py
# Secure Banking Application
# This implementation uses SQLite for simplicity, but the security principles apply to any database

import sqlite3
import hashlib
import os
import re
import logging
import time
import secrets
import pyotp  # For multi-factor authentication
import bcrypt  # For stronger password hashing
from cryptography.fernet import Fernet  # For encryption
import uuid  # For generating unique transaction IDs
from datetime import datetime
import getpass
# Optional QR code support - gracefully handle if not installed
try:
    import qrcode
    QR_CODE_AVAILABLE = True
except ImportError:
    QR_CODE_AVAILABLE = False
    print("Note: qrcode library not found. QR codes will not be available.")

from io import BytesIO
import base64

# Configure secure logging
logging.basicConfig(
    filename='bank_app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Security utility functions
def setup_encryption():
    """Generate or load encryption key for securing sensitive data"""
    key_file = 'encryption_key.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()
    else:
        # Generate a key and save it
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        
        # In production, this key should be stored securely, not in the filesystem
        # Consider using a key management service in real-world applications
    
    return Fernet(key)

# Set up encryption
cipher_suite = setup_encryption()

def encrypt_data(data):
    """Encrypt sensitive data"""
    if data is None:
        return None
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    if encrypted_data is None:
        return None
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

def hash_password(password):
    """Hash a password using bcrypt with salt"""
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def verify_password(stored_password, provided_password):
    """Verify a password against its hash"""
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

def validate_input(input_data, input_type):
    """Validate user input to prevent injection attacks"""
    if input_data is None:
        return False
        
    if input_type == "username":
        # Usernames should be alphanumeric with underscore
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return re.match(pattern, input_data) is not None
    
    elif input_type == "password":
        # Password should have at least 8 chars, with uppercase, lowercase, numbers, and special chars
        # Check length first
        if len(input_data) < 8:
            return False
            
        # Check for at least one uppercase, one lowercase, one digit, and one special character
        has_upper = any(c.isupper() for c in input_data)
        has_lower = any(c.islower() for c in input_data)
        has_digit = any(c.isdigit() for c in input_data)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in input_data)
        
        return has_upper and has_lower and has_digit and has_special
    
    elif input_type == "amount":
        # Amount should be a positive number
        try:
            amount = float(input_data)
            return amount > 0
        except ValueError:
            return False
    
    elif input_type == "email":
        # Basic email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, input_data) is not None
    
    elif input_type == "mfa_code":
        # MFA code should be 6 digits
        pattern = r'^\d{6}$'
        return re.match(pattern, input_data) is not None
    
    return False

def generate_transaction_id():
    """Generate a unique transaction ID"""
    return str(uuid.uuid4())

def secure_log(message, log_level="INFO", user=None):
    """Log messages securely without exposing sensitive information"""
    if user:
        # Mask sensitive data in logs
        message = f"User: {user} - {message}"
    
    if log_level == "INFO":
        logging.info(message)
    elif log_level == "WARNING":
        logging.warning(message)
    elif log_level == "ERROR":
        logging.error(message)
    elif log_level == "CRITICAL":
        logging.critical(message)

def generate_qr_code(secret, username, issuer="SecureBankApp"):
    """Generate QR code for MFA setup (if qrcode library is available)"""
    if not QR_CODE_AVAILABLE:
        return None, None
        
    try:
        # Create the provisioning URI
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        return qr, totp_uri
    except Exception as e:
        secure_log(f"Error generating QR code: {str(e)}", "ERROR")
        return None, None

# Database setup and migration
def check_and_migrate_database():
    """Check database schema and migrate if necessary"""
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    
    try:
        # Check if mfa_enabled column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'mfa_enabled' not in columns:
            secure_log("Adding mfa_enabled column to users table", "INFO")
            cursor.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 1")
        
        # Check if mfa_backup_codes table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='mfa_backup_codes'")
        if not cursor.fetchone():
            secure_log("Creating mfa_backup_codes table", "INFO")
            cursor.execute('''
            CREATE TABLE mfa_backup_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            ''')
        
        conn.commit()
        secure_log("Database migration completed successfully", "INFO")
        
    except sqlite3.Error as e:
        secure_log(f"Database migration error: {str(e)}", "ERROR")
        conn.rollback()
    finally:
        conn.close()

def setup_database():
    """Set up the SQLite database with secure schema"""
    # Check if database file exists
    db_exists = os.path.exists('bank.db')
    
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    
    # Create users table with password hashing
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        mfa_secret TEXT NOT NULL,
        mfa_enabled INTEGER DEFAULT 1,
        account_locked INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create accounts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        balance REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create secure transaction logs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        account_id INTEGER NOT NULL,
        transaction_type TEXT NOT NULL,
        amount REAL NOT NULL,
        previous_balance REAL NOT NULL,
        new_balance REAL NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        encrypted_details TEXT,
        hash_verification TEXT NOT NULL,
        FOREIGN KEY (account_id) REFERENCES accounts(id)
    )
    ''')
    
    # Create audit log for security events
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS security_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        user_id INTEGER,
        ip_address TEXT,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create MFA backup codes table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS mfa_backup_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code_hash TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    conn.commit()
    conn.close()
    
    # Run migration check
    check_and_migrate_database()
    
    # Log database creation/check
    if not db_exists:
        secure_log("Database created successfully", "INFO")
    else:
        secure_log("Database connection verified", "INFO")

# User authentication and management
class UserAuth:
    def __init__(self, db_path='bank.db'):
        self.db_path = db_path
        self.current_user = None
        self.current_user_id = None
    
    def connect_db(self):
        """Establish a secure database connection"""
        return sqlite3.connect(self.db_path)
    
    def generate_backup_codes(self, user_id):
        """Generate backup codes for MFA"""
        backup_codes = []
        try:
            conn = self.connect_db()
            cursor = conn.cursor()
            
            for _ in range(10):  # Generate 10 backup codes
                code = secrets.token_hex(4).upper()  # 8-character hex code
                code_hash = hashlib.sha256(code.encode()).hexdigest()
                
                cursor.execute(
                    "INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES (?, ?)",
                    (user_id, code_hash)
                )
                backup_codes.append(code)
            
            conn.commit()
            conn.close()
            return backup_codes
        except Exception as e:
            secure_log(f"Error generating backup codes: {str(e)}", "ERROR")
            return []
    
    def register_user(self, username, password, email):
        """Register a new user with secure password storage and mandatory MFA"""
        # Input validation
        if not validate_input(username, "username"):
            secure_log(f"Registration failed: Invalid username format", "WARNING")
            return False, "Invalid username format. Use alphanumeric characters (3-20 chars)."
        
        if not validate_input(password, "password"):
            secure_log(f"Registration failed: Weak password", "WARNING")
            return False, "Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters."
        
        if not validate_input(email, "email"):
            secure_log(f"Registration failed: Invalid email format", "WARNING")
            return False, "Invalid email format."
        
        secure_log(f"Starting registration for user: {username}", "INFO")
        
        # Hash the password
        password_hash = hash_password(password)
        
        # Generate a MFA secret
        mfa_secret = pyotp.random_base32()
        
        try:
            conn = self.connect_db()
            cursor = conn.cursor()
            
            # Check if username already exists (using parameterized query to prevent SQL injection)
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                conn.close()
                secure_log(f"Registration failed: Username {username} already exists", "WARNING")
                return False, "Username already exists."
            
            # Check if email already exists
            cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                conn.close()
                secure_log(f"Registration failed: Email already registered", "WARNING")
                return False, "Email already registered."
            
            secure_log(f"Inserting new user: {username}", "INFO")
            
            # Insert the new user
            cursor.execute(
                "INSERT INTO users (username, password_hash, email, mfa_secret, mfa_enabled) VALUES (?, ?, ?, ?, ?)",
                (username, password_hash, email, mfa_secret, 1)
            )
            
            # Get the user id
            user_id = cursor.lastrowid
            
            if not user_id:
                conn.rollback()
                conn.close()
                secure_log(f"Failed to get user_id for: {username}", "ERROR")
                return False, "Failed to create user account. Please try again."
            
            secure_log(f"User created with ID: {user_id}", "INFO")
            
            # Create a bank account for the user
            account_number = f"ACC-{secrets.token_hex(5).upper()}"
            cursor.execute(
                "INSERT INTO accounts (user_id, account_number, balance) VALUES (?, ?, ?)",
                (user_id, account_number, 0.0)
            )
            
            # Generate backup codes
            backup_codes = self.generate_backup_codes(user_id)
            
            conn.commit()
            
            # Verify the user was created
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                secure_log(f"Verification failed: User {username} not found after insert", "ERROR")
                conn.close()
                return False, "Registration failed. Please try again."
                
            conn.close()
            
            # Generate QR code for MFA setup
            qr_code, totp_uri = generate_qr_code(mfa_secret, username)
            
            secure_log(f"New user registered successfully: {username}", "INFO")
            
            success_message = f"""
User registered successfully!
Account Number: {account_number}

=== MFA SETUP REQUIRED ===
MFA Secret: {mfa_secret}

Please set up your authenticator app:
1. Install Google Authenticator, Authy, or similar app
2. Add account manually with this secret: {mfa_secret}
3. Account name: {username}
4. Issuer: SecureBankApp

Your backup codes (save these securely):
{', '.join(backup_codes)}

IMPORTANT: MFA is MANDATORY for login. Save your secret and backup codes!
"""
            
            # Try to display QR code if available
            if QR_CODE_AVAILABLE and qr_code:
                try:
                    print("\n=== QR CODE FOR MFA SETUP ===")
                    qr_code.print_ascii(invert=True)
                    print("=== END QR CODE ===\n")
                except Exception as e:
                    secure_log(f"QR code display error: {str(e)}", "WARNING")
            elif not QR_CODE_AVAILABLE:
                success_message += "\nNote: Install 'qrcode' library for QR code generation: pip install qrcode[pil]"
            
            return True, success_message
        
        except sqlite3.Error as e:
            secure_log(f"SQLite error during registration: {str(e)}", "ERROR")
            return False, f"Database error occurred: {str(e)}"
        except Exception as e:
            secure_log(f"Registration error: {str(e)}", "ERROR")
            return False, "An error occurred during registration."
    
    def verify_backup_code(self, user_id, backup_code):
        """Verify a backup code"""
        try:
            conn = self.connect_db()
            cursor = conn.cursor()
            
            code_hash = hashlib.sha256(backup_code.encode()).hexdigest()
            
            # Check if backup code exists and hasn't been used
            cursor.execute(
                "SELECT id FROM mfa_backup_codes WHERE user_id = ? AND code_hash = ? AND used = 0",
                (user_id, code_hash)
            )
            
            backup_code_record = cursor.fetchone()
            
            if backup_code_record:
                # Mark the backup code as used
                cursor.execute(
                    "UPDATE mfa_backup_codes SET used = 1 WHERE id = ?",
                    (backup_code_record[0],)
                )
                conn.commit()
                conn.close()
                return True
            
            conn.close()
            return False
            
        except Exception as e:
            secure_log(f"Error verifying backup code: {str(e)}", "ERROR")
            return False
    
    def login(self, username, password, mfa_code):
        """Authenticate a user with username, password and mandatory MFA"""
        try:
            conn = self.connect_db()
            cursor = conn.cursor()
            
            # Get user information
            cursor.execute(
                "SELECT id, username, password_hash, mfa_secret, account_locked, failed_attempts, mfa_enabled FROM users WHERE username = ?",
                (username,)
            )
            user = cursor.fetchone()
            
            if not user:
                secure_log(f"Login attempt with non-existent username: {username}", "WARNING")
                # Return generic message to prevent username enumeration
                return False, "Invalid username or password."
            
            user_id, db_username, password_hash, mfa_secret, account_locked, failed_attempts, mfa_enabled = user
            
            # Check if account is locked
            if account_locked:
                secure_log(f"Login attempt on locked account: {username}", "WARNING")
                return False, "Account is locked. Please contact support."
            
            # Verify the password
            if not verify_password(password_hash, password):
                # Increment failed attempts
                failed_attempts += 1
                
                # Lock the account after 5 failed attempts
                if failed_attempts >= 5:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = ?, account_locked = 1 WHERE id = ?",
                        (failed_attempts, user_id)
                    )
                    secure_log(f"Account locked due to multiple failed attempts: {username}", "WARNING")
                    conn.commit()
                    conn.close()
                    return False, "Too many failed attempts. Account locked."
                else:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = ? WHERE id = ?",
                        (failed_attempts, user_id)
                    )
                    conn.commit()
                
                secure_log(f"Failed login attempt for {username}. Attempt {failed_attempts}/5", "WARNING")
                conn.close()
                return False, "Invalid username or password."
            
            # Password is correct, now verify MFA (MANDATORY)
            if not mfa_code:
                secure_log(f"Login attempt without MFA code for {username}", "WARNING")
                conn.close()
                return False, "MFA code is required for login."
            
            # Validate MFA code format
            if not validate_input(mfa_code, "mfa_code"):
                # Check if it might be a backup code (8 characters)
                if len(mfa_code) == 8 and mfa_code.isalnum():
                    if self.verify_backup_code(user_id, mfa_code.upper()):
                        secure_log(f"Successful login with backup code: {username}", "INFO", username)
                    else:
                        secure_log(f"Failed backup code verification for {username}", "WARNING")
                        conn.close()
                        return False, "Invalid backup code."
                else:
                    secure_log(f"Invalid MFA code format for {username}", "WARNING")
                    conn.close()
                    return False, "Invalid MFA code format. Enter 6-digit code or 8-character backup code."
            else:
                # Verify TOTP code
                totp = pyotp.TOTP(mfa_secret)
                if not totp.verify(mfa_code, valid_window=1):  # Allow 30-second window
                    secure_log(f"Failed MFA verification for {username}", "WARNING")
                    conn.close()
                    return False, "Invalid MFA code."
            
            # Reset failed attempts and update last login
            cursor.execute(
                "UPDATE users SET failed_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,)
            )
            conn.commit()
            
            # Set current user
            self.current_user = username
            self.current_user_id = user_id
            
            secure_log(f"Successful login: {username}", "INFO", username)
            conn.close()
            return True, "Login successful."
            
        except Exception as e:
            secure_log(f"Login error: {str(e)}", "ERROR")
            return False, "An error occurred during login."
    
    def logout(self):
        """Log out the current user"""
        if not self.current_user:
            return False, "No user is logged in."
        
        username = self.current_user
        self.current_user = None
        self.current_user_id = None
        
        secure_log(f"User logged out: {username}", "INFO", username)
        return True, "Logged out successfully."
    
    def is_authenticated(self):
        """Check if a user is authenticated"""
        return self.current_user is not None and self.current_user_id is not None

# Banking operations
class BankOperations:
    def __init__(self, user_auth, db_path='bank.db'):
        self.user_auth = user_auth
        self.db_path = db_path
    
    def connect_db(self):
        """Establish a secure database connection"""
        return sqlite3.connect(self.db_path)
    
    def get_account_details(self):
        """Get account details for the current logged-in user"""
        if not self.user_auth.is_authenticated():
            secure_log("Unauthorized attempt to access account details", "WARNING")
            return False, "You must be logged in to view account details."
        
        try:
            conn = self.connect_db()
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT id, account_number, balance FROM accounts WHERE user_id = ?",
                (self.user_auth.current_user_id,)
            )
            
            accounts = cursor.fetchall()
            conn.close()
            
            if not accounts:
                secure_log(f"No accounts found for user: {self.user_auth.current_user}", "WARNING", self.user_auth.current_user)
                return False, "No accounts found."
            
            account_info = []
            for acc_id, acc_number, balance in accounts:
                account_info.append({
                    "id": acc_id,
                    "account_number": acc_number,
                    "balance": balance
                })
            
            secure_log(f"Account details viewed by: {self.user_auth.current_user}", "INFO", self.user_auth.current_user)
            return True, account_info
            
        except Exception as e:
            secure_log(f"Error getting account details: {str(e)}", "ERROR")
            return False, "An error occurred while retrieving account details."
    
    def deposit(self, amount, account_id=None):
        """Deposit money into the user's account"""
        if not self.user_auth.is_authenticated():
            secure_log("Unauthorized deposit attempt", "WARNING")
            return False, "You must be logged in to make a deposit."
        
        if not validate_input(str(amount), "amount"):
            secure_log(f"Invalid deposit amount attempted: {amount}", "WARNING", self.user_auth.current_user)
            return False, "Invalid amount. Please enter a positive number."
        
        try:
            amount = float(amount)
            
            conn = self.connect_db()
            cursor = conn.cursor()
            
            # Get account information
            if account_id:
                cursor.execute(
                    "SELECT id, balance, account_number FROM accounts WHERE id = ? AND user_id = ?",
                    (account_id, self.user_auth.current_user_id)
                )
            else:
                cursor.execute(
                    "SELECT id, balance, account_number FROM accounts WHERE user_id = ? LIMIT 1",
                    (self.user_auth.current_user_id,)
                )
            
            account = cursor.fetchone()
            
            if not account:
                conn.close()
                secure_log("Deposit to non-existent account", "WARNING", self.user_auth.current_user)
                return False, "Account not found."
            
            acc_id, current_balance, account_number = account
            
            # Generate transaction details
            transaction_id = generate_transaction_id()
            new_balance = current_balance + amount
            transaction_details = f"Deposit of ${amount:.2f} to account {account_number}"
            encrypted_details = encrypt_data(transaction_details)
            
            # Create a hash verification to ensure transaction integrity
            transaction_string = f"{transaction_id}|{acc_id}|deposit|{amount}|{current_balance}|{new_balance}|{datetime.now().isoformat()}"
            hash_verification = hashlib.sha256(transaction_string.encode()).hexdigest()
            
            # Update balance
            cursor.execute(
                "UPDATE accounts SET balance = ? WHERE id = ?",
                (new_balance, acc_id)
            )
            
            # Log the transaction
            cursor.execute(
                "INSERT INTO transactions (id, account_id, transaction_type, amount, previous_balance, new_balance, encrypted_details, hash_verification) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (transaction_id, acc_id, "deposit", amount, current_balance, new_balance, encrypted_details, hash_verification)
            )
            
            conn.commit()
            conn.close()
            
            secure_log(f"Deposit of ${amount:.2f} to account {account_number}", "INFO", self.user_auth.current_user)
            return True, f"Successfully deposited ${amount:.2f}. New balance: ${new_balance:.2f}"
            
        except Exception as e:
            secure_log(f"Deposit error: {str(e)}", "ERROR")
            return False, "An error occurred during the deposit."
    
    def withdraw(self, amount, account_id=None):
        """Withdraw money from the user's account"""
        if not self.user_auth.is_authenticated():
            secure_log("Unauthorized withdrawal attempt", "WARNING")
            return False, "You must be logged in to make a withdrawal."
        
        if not validate_input(str(amount), "amount"):
            secure_log(f"Invalid withdrawal amount attempted: {amount}", "WARNING", self.user_auth.current_user)
            return False, "Invalid amount. Please enter a positive number."
        
        try:
            amount = float(amount)
            
            conn = self.connect_db()
            cursor = conn.cursor()
            
            # Get account information
            if account_id:
                cursor.execute(
                    "SELECT id, balance, account_number FROM accounts WHERE id = ? AND user_id = ?",
                    (account_id, self.user_auth.current_user_id)
                )
            else:
                cursor.execute(
                    "SELECT id, balance, account_number FROM accounts WHERE user_id = ? LIMIT 1",
                    (self.user_auth.current_user_id,)
                )
            
            account = cursor.fetchone()
            
            if not account:
                conn.close()
                secure_log("Withdrawal from non-existent account", "WARNING", self.user_auth.current_user)
                return False, "Account not found."
            
            acc_id, current_balance, account_number = account
            
            # Check if there are sufficient funds
            if current_balance < amount:
                conn.close()
                secure_log(f"Insufficient funds for withdrawal: {amount}", "WARNING", self.user_auth.current_user)
                return False, "Insufficient funds."
            
            # Generate transaction details
            transaction_id = generate_transaction_id()
            new_balance = current_balance - amount
            transaction_details = f"Withdrawal of ${amount:.2f} from account {account_number}"
            encrypted_details = encrypt_data(transaction_details)
            
            # Create a hash verification to ensure transaction integrity
            transaction_string = f"{transaction_id}|{acc_id}|withdrawal|{amount}|{current_balance}|{new_balance}|{datetime.now().isoformat()}"
            hash_verification = hashlib.sha256(transaction_string.encode()).hexdigest()
            
            # Update balance
            cursor.execute(
                "UPDATE accounts SET balance = ? WHERE id = ?",
                (new_balance, acc_id)
            )
            
            # Log the transaction
            cursor.execute(
                "INSERT INTO transactions (id, account_id, transaction_type, amount, previous_balance, new_balance, encrypted_details, hash_verification) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (transaction_id, acc_id, "withdrawal", amount, current_balance, new_balance, encrypted_details, hash_verification)
            )
            
            conn.commit()
            conn.close()
            
            secure_log(f"Withdrawal of ${amount:.2f} from account {account_number}", "INFO", self.user_auth.current_user)
            return True, f"Successfully withdrew ${amount:.2f}. New balance: ${new_balance:.2f}"
            
        except Exception as e:
            secure_log(f"Withdrawal error: {str(e)}", "ERROR")
            return False, "An error occurred during the withdrawal."
    
    def get_transaction_history(self, account_id=None):
        """Get transaction history for an account"""
        if not self.user_auth.is_authenticated():
            secure_log("Unauthorized attempt to access transaction history", "WARNING")
            return False, "You must be logged in to view transaction history."
        
        try:
            conn = self.connect_db()
            cursor = conn.cursor()
            
            # Get account information
            if account_id:
                cursor.execute(
                    "SELECT id FROM accounts WHERE id = ? AND user_id = ?",
                    (account_id, self.user_auth.current_user_id)
                )
            else:
                cursor.execute(
                    "SELECT id FROM accounts WHERE user_id = ? LIMIT 1",
                    (self.user_auth.current_user_id,)
                )
            
            account = cursor.fetchone()
            
            if not account:
                conn.close()
                secure_log("Transaction history request for non-existent account", "WARNING", self.user_auth.current_user)
                return False, "Account not found."
            
            acc_id = account[0]
            
            # Get transactions
            cursor.execute(
                "SELECT id, transaction_type, amount, previous_balance, new_balance, timestamp, encrypted_details FROM transactions WHERE account_id = ? ORDER BY timestamp DESC LIMIT 10",
                (acc_id,)
            )
            
            transactions = cursor.fetchall()
            conn.close()
            
            if not transactions:
                return True, "No transaction history found."
            
            transaction_history = []
            for t_id, t_type, amount, prev_balance, new_balance, timestamp, encrypted_details in transactions:
                transaction = {
                    "id": t_id,
                    "type": t_type,
                    "amount": amount,
                    "previous_balance": prev_balance,
                    "new_balance": new_balance,
                    "timestamp": timestamp,
                    "details": decrypt_data(encrypted_details) if encrypted_details else None
                }
                transaction_history.append(transaction)
            
            secure_log(f"Transaction history viewed by: {self.user_auth.current_user}", "INFO", self.user_auth.current_user)
            return True, transaction_history
            
        except Exception as e:
            secure_log(f"Error getting transaction history: {str(e)}", "ERROR")
            return False, "An error occurred while retrieving transaction history."

    def verify_transaction_integrity(self, transaction_id):
        """Verify the integrity of a transaction using its hash"""
        if not self.user_auth.is_authenticated():
            secure_log("Unauthorized attempt to verify transaction", "WARNING")
            return False, "You must be logged in to verify transactions."
        
        try:
            conn = self.connect_db()
            cursor = conn.cursor()
            
            # Get transaction details
            cursor.execute(
                """
                SELECT t.id, t.account_id, t.transaction_type, t.amount, t.previous_balance, t.new_balance, 
                       t.timestamp, t.hash_verification, a.user_id 
                FROM transactions t
                JOIN accounts a ON t.account_id = a.id
                WHERE t.id = ?
                """,
                (transaction_id,)
            )
            
            transaction = cursor.fetchone()
            
            if not transaction:
                conn.close()
                secure_log(f"Verification attempt for non-existent transaction: {transaction_id}", "WARNING", self.user_auth.current_user)
                return False, "Transaction not found."
            
            t_id, acc_id, t_type, amount, prev_balance, new_balance, timestamp, hash_verification, user_id = transaction
            
            # Check if user has access to this transaction
            if user_id != self.user_auth.current_user_id:
                conn.close()
                secure_log(f"Unauthorized verification attempt for transaction: {transaction_id}", "WARNING", self.user_auth.current_user)
                return False, "You don't have permission to verify this transaction."
            
            # Recalculate the hash
            transaction_string = f"{t_id}|{acc_id}|{t_type}|{amount}|{prev_balance}|{new_balance}|{timestamp}"
            calculated_hash = hashlib.sha256(transaction_string.encode()).hexdigest()
            
            # Compare hashes
            if calculated_hash == hash_verification:
                secure_log(f"Transaction verified successfully: {transaction_id}", "INFO", self.user_auth.current_user)
                conn.close()
                return True, "Transaction verified. Integrity confirmed."
            else:
                secure_log(f"Transaction verification failed: {transaction_id}", "WARNING", self.user_auth.current_user)
                conn.close()
                return False, "Transaction verification failed. Possible tampering detected."
            
        except Exception as e:
            secure_log(f"Error verifying transaction: {str(e)}", "ERROR")
            return False, "An error occurred during transaction verification."

# Main application class
class BankingApp:
    def __init__(self):
        try:
            # Initialize database
            setup_database()
            
            # Test database connection
            conn = sqlite3.connect('bank.db')
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            if not tables or len(tables) < 5:  # We expect at least 5 tables now
                secure_log("Database tables not properly created", "ERROR")
                print("Error initializing database. Please check logs.")
            conn.close()
            
            # Initialize authentication module
            self.user_auth = UserAuth()
            
            # Initialize banking operations
            self.bank_ops = BankOperations(self.user_auth)
            
            secure_log("Application initialized successfully", "INFO")
        except sqlite3.Error as e:
            secure_log(f"Database error during initialization: {str(e)}", "CRITICAL")
            print(f"Critical database error: {str(e)}")
            raise
        except Exception as e:
            secure_log(f"Application initialization error: {str(e)}", "CRITICAL")
            print(f"Critical error initializing application: {str(e)}")
            raise
    
    def run(self):
        """Run the banking application with a simple CLI interface"""
        print("\n===== Secure Banking Application =====")
        print("Version 2.0 - Mandatory MFA with Backup Codes")
        
        while True:
            if self.user_auth.is_authenticated():
                self.show_authenticated_menu()
            else:
                self.show_unauthenticated_menu()
    
    def show_unauthenticated_menu(self):
        """Display menu for unauthenticated users"""
        print("\n--- Main Menu ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == "1":
            self.register_user()
        elif choice == "2":
            self.login_user()
        elif choice == "3":
            print("Thank you for using Secure Banking App. Goodbye!")
            exit(0)
        else:
            print("Invalid choice. Please try again.")
    
    def show_authenticated_menu(self):
        """Display menu for authenticated users"""
        print(f"\n--- Welcome, {self.user_auth.current_user} ---")
        print("1. View Account Details")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. Transaction History")
        print("5. Verify Transaction")
        print("6. Logout")
        
        choice = input("\nEnter your choice (1-6): ")
        
        if choice == "1":
            self.show_account_details()
        elif choice == "2":
            self.make_deposit()
        elif choice == "3":
            self.make_withdrawal()
        elif choice == "4":
            self.show_transaction_history()
        elif choice == "5":
            self.verify_transaction()
        elif choice == "6":
            success, message = self.user_auth.logout()
            print(message)
        else:
            print("Invalid choice. Please try again.")
    
    def register_user(self):
        """Register a new user"""
        print("\n--- User Registration ---")
        
        # Get username
        username = input("Enter username (alphanumeric with underscore, 3-20 chars): ")
        if not validate_input(username, "username"):
            print("Invalid username format. Use alphanumeric characters and underscore (3-20 chars).")
            return
        
        # Prompt for password with requirements
        print("Password requirements: at least 8 characters with uppercase, lowercase, numbers, and special characters")
        password = getpass.getpass("Enter password: ")
        
        # Validate password immediately
        if not validate_input(password, "password"):
            print("Password does not meet requirements. Please try again.")
            return
            
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            return
        
        email = input("Enter email: ")
        if not validate_input(email, "email"):
            print("Invalid email format. Please try again.")
            return
        
        # Display processing message
        print("Processing registration...")
        
        # Attempt to register the user
        success, message = self.user_auth.register_user(username, password, email)
        print(message)
        
        # If successful, provide clear confirmation
        if success:
            print("\nRegistration successful! Please set up your authenticator app before logging in.")
            print("MFA is MANDATORY for all logins.")
    
    def login_user(self):
        """Login an existing user"""
        print("\n--- User Login ---")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        
        print("\nMFA is required for login.")
        print("Enter your 6-digit authenticator code OR 8-character backup code:")
        mfa_code = input("MFA Code: ")
        
        if not mfa_code.strip():
            print("MFA code is required. Login cancelled.")
            return
        
        print("Authenticating...")
        success, message = self.user_auth.login(username, password, mfa_code.strip())
        print(message)
    
    def show_account_details(self):
        """Show account details for the current user"""
        success, result = self.bank_ops.get_account_details()
        
        if success:
            print("\n--- Account Details ---")
            for account in result:
                print(f"Account Number: {account['account_number']}")
                print(f"Balance: ${account['balance']:.2f}")
        else:
            print(result)
    
    def make_deposit(self):
        """Make a deposit to the user's account"""
        print("\n--- Deposit ---")
        
        try:
            amount = input("Enter amount to deposit: $")
            
            if not amount.strip():
                print("Amount cannot be empty. Please try again.")
                return
                
            success, message = self.bank_ops.deposit(amount)
            print(message)
        except Exception as e:
            print(f"Error during deposit: {str(e)}")
            secure_log(f"Error in make_deposit UI: {str(e)}", "ERROR")
    
    def make_withdrawal(self):
        """Make a withdrawal from the user's account"""
        print("\n--- Withdrawal ---")
        
        try:
            amount = input("Enter amount to withdraw: $")
            
            if not amount.strip():
                print("Amount cannot be empty. Please try again.")
                return
                
            success, message = self.bank_ops.withdraw(amount)
            print(message)
        except Exception as e:
            print(f"Error during withdrawal: {str(e)}")
            secure_log(f"Error in make_withdrawal UI: {str(e)}", "ERROR")
    
    def show_transaction_history(self):
        """Show transaction history"""
        success, result = self.bank_ops.get_transaction_history()
        
        if success and isinstance(result, list):
            print("\n--- Transaction History ---")
            for transaction in result:
                print(f"ID: {transaction['id']}")
                print(f"Type: {transaction['type']}")
                print(f"Amount: ${transaction['amount']:.2f}")
                print(f"Balance Before: ${transaction['previous_balance']:.2f}")
                print(f"Balance After: ${transaction['new_balance']:.2f}")
                print(f"Timestamp: {transaction['timestamp']}")
                if transaction['details']:
                    print(f"Details: {transaction['details']}")
                print("-" * 30)
        else:
            print(result)
    
    def verify_transaction(self):
        """Verify a transaction's integrity"""
        print("\n--- Verify Transaction ---")
        transaction_id = input("Enter transaction ID: ")
        
        success, message = self.bank_ops.verify_transaction_integrity(transaction_id)
        print(message)

# Run the application if executed directly
if __name__ == "__main__":
    try:
        app = BankingApp()
        app.run()
    except KeyboardInterrupt:
        print("\n\nApplication terminated by user.")
    except Exception as e:
        secure_log(f"Critical application error: {str(e)}", "CRITICAL")
        print(f"Critical application error: {str(e)}")
        print("Please check the logs for more details.")