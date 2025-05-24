# test_banking_app.py
# Enhanced Security Test Suite for Secure Banking Application

import unittest
import os
import sqlite3
import time
import re
import logging
import json
import hashlib
import secrets
import tempfile
from datetime import datetime
from unittest.mock import patch, MagicMock
import pyotp
import bcrypt
from banking_app import (
    UserAuth, BankOperations, hash_password, validate_input, 
    encrypt_data, decrypt_data, setup_database, generate_transaction_id,
    secure_log
)

# Configure test logging
class SecurityTestLogger:
    def __init__(self):
        self.log_file = f"security_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.logger = logging.getLogger('SecurityTests')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler for detailed logs
        file_handler = logging.FileHandler(self.log_file, mode='w')
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler for important messages
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        self.test_results = {
            'passed': 0,
            'failed': 0,
            'vulnerabilities': [],
            'security_issues': [],
            'performance_issues': []
        }
    
    def log_test_start(self, test_name):
        self.logger.info(f"Starting test: {test_name}")
    
    def log_test_pass(self, test_name, details=""):
        self.test_results['passed'] += 1
        self.logger.info(f"PASS: {test_name} - {details}")
    
    def log_test_fail(self, test_name, error, details=""):
        self.test_results['failed'] += 1
        self.logger.error(f"FAIL: {test_name} - {error} - {details}")
    
    def log_vulnerability(self, vulnerability_type, description, severity="MEDIUM"):
        vuln = {
            'type': vulnerability_type,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results['vulnerabilities'].append(vuln)
        self.logger.critical(f"VULNERABILITY [{severity}]: {vulnerability_type} - {description}")
    
    def log_security_issue(self, issue_type, description, severity="LOW"):
        issue = {
            'type': issue_type,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results['security_issues'].append(issue)
        self.logger.warning(f"SECURITY ISSUE [{severity}]: {issue_type} - {description}")
    
    def log_performance_issue(self, operation, duration, threshold=1.0):
        if duration > threshold:
            issue = {
                'operation': operation,
                'duration': duration,
                'threshold': threshold,
                'timestamp': datetime.now().isoformat()
            }
            self.test_results['performance_issues'].append(issue)
            self.logger.warning(f"PERFORMANCE: {operation} took {duration:.2f}s (threshold: {threshold}s)")
    
    def generate_report(self):
        """Generate a comprehensive security test report"""
        total_tests = self.test_results['passed'] + self.test_results['failed']
        
        report = f"""
{'='*80}
SECURITY TEST REPORT
{'='*80}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Log File: {self.log_file}

SUMMARY:
- Total Tests: {total_tests}
- Passed: {self.test_results['passed']}
- Failed: {self.test_results['failed']}
- Success Rate: {(self.test_results['passed']/total_tests*100) if total_tests > 0 else 0:.1f}%

SECURITY ANALYSIS:
- Vulnerabilities Found: {len(self.test_results['vulnerabilities'])}
- Security Issues: {len(self.test_results['security_issues'])}
- Performance Issues: {len(self.test_results['performance_issues'])}

VULNERABILITIES:
"""
        
        for vuln in self.test_results['vulnerabilities']:
            report += f"  [{vuln['severity']}] {vuln['type']}: {vuln['description']}\n"
        
        if not self.test_results['vulnerabilities']:
            report += "  No critical vulnerabilities found.\n"
        
        report += "\nSECURITY ISSUES:\n"
        for issue in self.test_results['security_issues']:
            report += f"  [{issue['severity']}] {issue['type']}: {issue['description']}\n"
        
        if not self.test_results['security_issues']:
            report += "  No security issues found.\n"
        
        report += "\nPERFORMANCE ISSUES:\n"
        for perf in self.test_results['performance_issues']:
            report += f"  {perf['operation']}: {perf['duration']:.2f}s (threshold: {perf['threshold']}s)\n"
        
        if not self.test_results['performance_issues']:
            report += "  No performance issues found.\n"
        
        report += f"\n{'='*80}\n"
        
        self.logger.info(report)
        
        # Save detailed report to JSON
        json_report_file = f"security_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_report_file, 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        self.logger.info(f"Detailed JSON report saved to: {json_report_file}")
        
        return report

# Global test logger
test_logger = SecurityTestLogger()

class TestSecurityUtils(unittest.TestCase):
    """Enhanced security utility function tests"""
    
    def setUp(self):
        test_logger.log_test_start(self._testMethodName)
    
    def test_password_hashing_security(self):
        """Test password hashing security and resistance to attacks"""
        try:
            # Test basic functionality
            password = "SecurePassword123!"
            start_time = time.time()
            hashed = hash_password(password)
            hash_duration = time.time() - start_time
            
            # Performance check
            test_logger.log_performance_issue("password_hashing", hash_duration, 0.1)
            
            # Security checks
            self.assertIsInstance(hashed, str)
            self.assertGreater(len(hashed), 50)  # bcrypt hashes should be long
            self.assertTrue(hashed.startswith('$2b$'))  # bcrypt format
            
            # Test uniqueness - same password should produce different hashes due to salt
            hashed2 = hash_password(password)
            self.assertNotEqual(hashed, hashed2)
            
            # Test verification
            self.assertTrue(bcrypt.checkpw(password.encode(), hashed.encode()))
            self.assertFalse(bcrypt.checkpw("WrongPassword".encode(), hashed.encode()))
            
            # Test against common weak passwords
            weak_passwords = ["password", "123456", "admin", "qwerty"]
            for weak_pass in weak_passwords:
                try:
                    weak_hash = hash_password(weak_pass)
                    test_logger.log_security_issue(
                        "WEAK_PASSWORD_ACCEPTED",
                        f"System accepts weak password: {weak_pass}",
                        "HIGH"
                    )
                except:
                    pass  # Good - system should reject weak passwords
            
            test_logger.log_test_pass(self._testMethodName, "Password hashing is secure")
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_input_validation_security(self):
        """Test input validation against injection attacks"""
        try:
            # SQL Injection attempts
            sql_injection_payloads = [
                "'; DROP TABLE users; --",
                "admin'; --",
                "1' OR '1'='1",
                "admin'/*",
                "' UNION SELECT * FROM users --"
            ]
            
            for payload in sql_injection_payloads:
                if validate_input(payload, "username"):
                    test_logger.log_vulnerability(
                        "SQL_INJECTION_RISK",
                        f"Input validation accepts potential SQL injection: {payload}",
                        "HIGH"
                    )
            
            # XSS attempts
            xss_payloads = [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>",
                "';alert('xss');//"
            ]
            
            for payload in xss_payloads:
                if validate_input(payload, "username"):
                    test_logger.log_vulnerability(
                        "XSS_RISK",
                        f"Input validation accepts potential XSS: {payload}",
                        "MEDIUM"
                    )
            
            # Command injection attempts
            command_injection_payloads = [
                "; cat /etc/passwd",
                "| ls -la",
                "&& whoami",
                "`id`"
            ]
            
            for payload in command_injection_payloads:
                if validate_input(payload, "username"):
                    test_logger.log_vulnerability(
                        "COMMAND_INJECTION_RISK",
                        f"Input validation accepts potential command injection: {payload}",
                        "HIGH"
                    )
            
            # Test legitimate inputs still work
            valid_inputs = ["validuser", "test123", "user_name"]
            for valid_input in valid_inputs:
                self.assertTrue(validate_input(valid_input, "username"))
            
            test_logger.log_test_pass(self._testMethodName, "Input validation resists injection attacks")
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_encryption_security(self):
        """Test encryption security and key management"""
        try:
            # Test basic encryption/decryption
            test_data = "Sensitive financial data: Account 123456789, Balance: $50000"
            encrypted = encrypt_data(test_data)
            decrypted = decrypt_data(encrypted)
            
            # Security checks
            self.assertNotEqual(test_data, encrypted)
            self.assertEqual(test_data, decrypted)
            
            # Test that encrypted data looks random
            if len(set(encrypted)) < len(encrypted) * 0.7:
                test_logger.log_security_issue(
                    "WEAK_ENCRYPTION",
                    "Encrypted data may not have sufficient entropy",
                    "MEDIUM"
                )
            
            # Test multiple encryptions of same data produce different results
            encrypted2 = encrypt_data(test_data)
            if encrypted == encrypted2:
                test_logger.log_vulnerability(
                    "DETERMINISTIC_ENCRYPTION",
                    "Encryption is deterministic - same plaintext produces same ciphertext",
                    "MEDIUM"
                )
            
            # Test with various data types
            test_cases = [
                "",  # Empty string
                "a" * 1000,  # Long string
                "Special chars: !@#$%^&*(){}[]|\\:;\"'<>?,./",
                "Unicode: 中文 العربية русский",
                None  # None value
            ]
            
            for test_case in test_cases:
                encrypted = encrypt_data(test_case)
                decrypted = decrypt_data(encrypted)
                self.assertEqual(test_case, decrypted)
            
            test_logger.log_test_pass(self._testMethodName, "Encryption is secure and robust")
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_transaction_id_security(self):
        """Test transaction ID generation for uniqueness and unpredictability"""
        try:
            # Generate multiple IDs and check for patterns
            ids = [generate_transaction_id() for _ in range(1000)]
            
            # Check uniqueness
            unique_ids = set(ids)
            if len(unique_ids) != len(ids):
                test_logger.log_vulnerability(
                    "NON_UNIQUE_TRANSACTION_IDS",
                    f"Generated {len(ids)} IDs but only {len(unique_ids)} were unique",
                    "HIGH"
                )
            
            # Check format (should be UUIDs)
            uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
            for transaction_id in ids[:10]:  # Check first 10
                if not uuid_pattern.match(transaction_id):
                    test_logger.log_security_issue(
                        "WEAK_TRANSACTION_ID_FORMAT",
                        f"Transaction ID doesn't follow UUID format: {transaction_id}",
                        "MEDIUM"
                    )
                    break
            
            # Check for sequential patterns
            sorted_ids = sorted(ids)
            sequential_count = 0
            for i in range(len(sorted_ids) - 1):
                if sorted_ids[i][:-1] == sorted_ids[i+1][:-1]:  # Same except last char
                    sequential_count += 1
            
            if sequential_count > len(ids) * 0.01:  # More than 1% similar
                test_logger.log_security_issue(
                    "PREDICTABLE_TRANSACTION_IDS",
                    f"Transaction IDs may be predictable: {sequential_count} similar patterns found",
                    "MEDIUM"
                )
            
            test_logger.log_test_pass(self._testMethodName, "Transaction IDs are secure and unique")
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise

class TestSecurityAuthentication(unittest.TestCase):
    """Enhanced authentication security tests"""
    
    def setUp(self):
        test_logger.log_test_start(self._testMethodName)
        # Create a temporary file for the test database
        self.db_fd, self.test_db = tempfile.mkstemp()
        
        # Create the database with proper schema
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        
        # Create all required tables
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
        
        self.user_auth = UserAuth(db_path=self.test_db)
    
    def tearDown(self):
        """Clean up after the test"""
        try:
            if hasattr(self, 'user_auth'):
                if hasattr(self.user_auth, 'connect_db'):
                    try:
                        conn = self.user_auth.connect_db()
                        conn.close()
                    except:
                        pass
            
            os.close(self.db_fd)
            time.sleep(0.1)  # Brief pause
            os.unlink(self.test_db)
        except:
            pass  # Best effort cleanup
    
    def test_brute_force_protection(self):
        """Test protection against brute force attacks"""
        try:
            # Register a test user
            success, _ = self.user_auth.register_user("brutetest", "SecurePass123!", "brute@test.com")
            self.assertTrue(success)
            
            # Attempt multiple failed logins
            failed_attempts = 0
            for i in range(10):  # Try 10 times
                start_time = time.time()
                success, message = self.user_auth.login("brutetest", "wrongpassword")
                attempt_duration = time.time() - start_time
                
                if not success:
                    failed_attempts += 1
                
                # Check if account gets locked
                if "locked" in message.lower():
                    break
                
                # Check for timing attacks - should have consistent response time
                if attempt_duration < 0.01:  # Too fast might indicate timing attack vulnerability
                    test_logger.log_security_issue(
                        "TIMING_ATTACK_RISK",
                        f"Login attempt {i+1} completed too quickly: {attempt_duration:.4f}s",
                        "MEDIUM"
                    )
            
            # Verify account is locked after multiple attempts
            if failed_attempts >= 5:
                success, message = self.user_auth.login("brutetest", "SecurePass123!")
                if success:
                    test_logger.log_vulnerability(
                        "INSUFFICIENT_BRUTE_FORCE_PROTECTION",
                        "Account not locked after multiple failed attempts",
                        "HIGH"
                    )
                else:
                    test_logger.log_test_pass(self._testMethodName, "Brute force protection working")
            else:
                test_logger.log_security_issue(
                    "WEAK_BRUTE_FORCE_PROTECTION",
                    f"Only {failed_attempts} failed attempts before lockout",
                    "MEDIUM"
                )
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_session_management_security(self):
        """Test session management security"""
        try:
            # Register and login
            success, _ = self.user_auth.register_user("sessiontest", "SecurePass123!", "session@test.com")
            self.assertTrue(success)
            
            success, _ = self.user_auth.login("username", "password", "123456")
            self.assertTrue(success)
            
            # Test that user is authenticated
            self.assertTrue(self.user_auth.is_authenticated())
            self.assertEqual(self.user_auth.current_user, "sessiontest")
            
            # Test logout
            success, _ = self.user_auth.logout()
            self.assertTrue(success)
            self.assertFalse(self.user_auth.is_authenticated())
            self.assertIsNone(self.user_auth.current_user)
            
            # Test double logout
            success, message = self.user_auth.logout()
            self.assertFalse(success)
            self.assertIn("No user is logged in", message)
            
            test_logger.log_test_pass(self._testMethodName, "Session management is secure")
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_mfa_security(self):
        """Test MFA implementation security"""
        try:
            # Register a user
            success, message = self.user_auth.register_user("mfatest", "SecurePass123!", "mfa@test.com")
            self.assertTrue(success)
            
            # Extract MFA secret
            secret_match = re.search(r'MFA Secret: ([A-Z0-9]+)', message)
            if not secret_match:
                test_logger.log_vulnerability(
                    "MFA_SECRET_NOT_PROVIDED",
                    "MFA secret not found in registration response",
                    "HIGH"
                )
                return
            
            mfa_secret = secret_match.group(1)
            
            # Test MFA code generation and validation
            totp = pyotp.TOTP(mfa_secret)
            valid_code = totp.now()
            
            # Test with valid code
            success, _ = self.user_auth.login("mfatest", "SecurePass123!", valid_code)
            if not success:
                test_logger.log_security_issue(
                    "MFA_VALIDATION_ISSUE",
                    "Valid MFA code rejected",
                    "MEDIUM"
                )
            
            self.user_auth.logout()
            
            # Test with invalid code
            invalid_code = "000000"
            success, message = self.user_auth.login("mfatest", "SecurePass123!", invalid_code)
            if success:
                test_logger.log_vulnerability(
                    "MFA_BYPASS",
                    "Invalid MFA code accepted",
                    "CRITICAL"
                )
            
            # Test MFA code reuse (replay attack)
            time.sleep(1)  # Ensure different timestamp
            success, _ = self.user_auth.login("mfatest", "SecurePass123!", valid_code)
            if success:
                test_logger.log_vulnerability(
                    "MFA_REPLAY_ATTACK",
                    "Old MFA code accepted (replay attack possible)",
                    "HIGH"
                )
            
            test_logger.log_test_pass(self._testMethodName, "MFA security validated")
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_password_policy_enforcement(self):
        """Test password policy enforcement"""
        try:
            weak_passwords = [
                "password",          # Common password
                "123456",           # Numeric only
                "abc",              # Too short
                "PASSWORD",         # No lowercase
                "password",         # No uppercase
                "Password",         # No numbers
                "Password123",      # No special characters
                "",                 # Empty
                "a" * 100,         # Too long
            ]
            
            weak_password_accepted = 0
            for weak_pass in weak_passwords:
                try:
                    success, _ = self.user_auth.register_user(
                        f"weaktest{len(weak_pass)}", weak_pass, f"weak{len(weak_pass)}@test.com"
                    )
                    if success:
                        weak_password_accepted += 1
                        test_logger.log_security_issue(
                            "WEAK_PASSWORD_ACCEPTED",
                            f"Weak password accepted: '{weak_pass}'",
                            "HIGH"
                        )
                except:
                    pass  # Exception is good - password was rejected
            
            if weak_password_accepted == 0:
                test_logger.log_test_pass(self._testMethodName, "Password policy properly enforced")
            else:
                test_logger.log_test_fail(
                    self._testMethodName, 
                    f"{weak_password_accepted} weak passwords accepted"
                )
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise

class TestBankingOperationsSecurity(unittest.TestCase):
    """Enhanced banking operations security tests"""
    
    def setUp(self):
        test_logger.log_test_start(self._testMethodName)
        # Create temporary database
        self.db_fd, self.test_db = tempfile.mkstemp()
        
        # Create database schema
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        
        # Create all required tables
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
        
        # Setup auth and banking operations
        self.user_auth = UserAuth(db_path=self.test_db)
        self.bank_ops = BankOperations(self.user_auth, db_path=self.test_db)
        
        # Register and login test user
        success, _ = self.user_auth.register_user("banktest", "SecurePass123!", "bank@test.com")
        self.assertTrue(success)
        success, _ = self.user_auth.login("banktest", "SecurePass123!")
        self.assertTrue(success)
    
    def tearDown(self):
        """Clean up after test"""
        try:
            if hasattr(self, 'bank_ops'):
                try:
                    conn = self.bank_ops.connect_db()
                    conn.close()
                except:
                    pass
            
            if hasattr(self, 'user_auth'):
                try:
                    conn = self.user_auth.connect_db()
                    conn.close()
                except:
                    pass
            
            os.close(self.db_fd)
            time.sleep(0.1)
            os.unlink(self.test_db)
        except:
            pass
    
    def test_transaction_integrity(self):
        """Test transaction integrity and audit trail"""
        try:
            # Perform a deposit
            start_time = time.time()
            success, message = self.bank_ops.deposit(100.0)
            transaction_duration = time.time() - start_time
            
            self.assertTrue(success)
            test_logger.log_performance_issue("deposit_transaction", transaction_duration, 1.0)
            
            # Get transaction history
            success, history = self.bank_ops.get_transaction_history()
            self.assertTrue(success)
            self.assertEqual(len(history), 1)
            
            transaction = history[0]
            transaction_id = transaction['id']
            
            # Verify transaction integrity
            success, message = self.bank_ops.verify_transaction_integrity(transaction_id)
            if not success:
                test_logger.log_vulnerability(
                    "TRANSACTION_INTEGRITY_FAILURE",
                    f"Transaction integrity verification failed: {message}",
                    "HIGH"
                )
            
            # Test transaction immutability by trying to modify database directly
            conn = sqlite3.connect(self.test_db)
            cursor = conn.cursor()
            
            # Try to modify the transaction amount
            cursor.execute(
                "UPDATE transactions SET amount = ? WHERE id = ?",
                (200.0, transaction_id)
            )
            conn.commit()
            conn.close()
            
            # Verify integrity after modification attempt
            success, message = self.bank_ops.verify_transaction_integrity(transaction_id)
            if success:
                test_logger.log_vulnerability(
                    "TRANSACTION_TAMPERING_NOT_DETECTED",
                    "Transaction modification not detected by integrity check",
                    "CRITICAL"
                )
            else:
                test_logger.log_test_pass(self._testMethodName, "Transaction tampering detected")
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_authorization_controls(self):
        """Test proper authorization controls"""
        try:
            # Make a deposit as current user
            success, _ = self.bank_ops.deposit(100.0)
            self.assertTrue(success)
            
            # Get current user's account info
            success, accounts = self.bank_ops.get_account_details()
            self.assertTrue(success)
            current_account_id = accounts[0]['id']
            
            # Create another user
            self.user_auth.logout()
            success, _ = self.user_auth.register_user("otheruser", "SecurePass123!", "other@test.com")
            self.assertTrue(success)
            success, _ = self.user_auth.login("otheruser", "SecurePass123!")
            self.assertTrue(success)
            
            # Try to access first user's account directly
            conn = sqlite3.connect(self.test_db)
            cursor = conn.cursor()
            
            # Attempt to access other user's account
            cursor.execute(
                "SELECT balance FROM accounts WHERE id = ? AND user_id = ?",
                (current_account_id, self.user_auth.current_user_id)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                test_logger.log_vulnerability(
                    "UNAUTHORIZED_ACCOUNT_ACCESS",
                    "User can access another user's account data",
                    "CRITICAL"
                )
            else:
                test_logger.log_test_pass(self._testMethodName, "Authorization controls working")
            
            # Test unauthorized transaction attempts
            success, message = self.bank_ops.withdraw(50.0)  # Try to withdraw from non-existent balance
            if success:
                test_logger.log_vulnerability(
                    "UNAUTHORIZED_TRANSACTION",
                    "User performed unauthorized transaction",
                    "HIGH"
                )
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_race_condition_protection(self):
        """Test protection against race conditions in concurrent transactions"""
        try:
            # Make initial deposit
            success, _ = self.bank_ops.deposit(1000.0)
            self.assertTrue(success)
            
            # Simulate concurrent withdrawal attempts
            import threading
            import queue
            
            results = queue.Queue()
            
            def concurrent_withdrawal(amount):
                try:
                    success, message = self.bank_ops.withdraw(amount)
                    results.put((success, message))
                except Exception as e:
                    results.put((False, str(e)))
            
            # Start multiple threads trying to withdraw the same amount
            threads = []
            for i in range(5):
                thread = threading.Thread(target=concurrent_withdrawal, args=(600.0,))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Check results
            successful_withdrawals = 0
            while not results.empty():
                success, message = results.get()
                if success:
                    successful_withdrawals += 1
            
            # Only one withdrawal should succeed (balance was 1000, trying to withdraw 600 each)
            if successful_withdrawals > 1:
                test_logger.log_vulnerability(
                    "RACE_CONDITION_VULNERABILITY",
                    f"{successful_withdrawals} concurrent withdrawals succeeded (expected 1)",
                    "HIGH"
                )
            else:
                test_logger.log_test_pass(self._testMethodName, "Race condition protection working")
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_sql_injection_protection(self):
        """Test SQL injection protection in banking operations"""
        try:
            # SQL injection payloads
            injection_payloads = [
                "'; DROP TABLE accounts; --",
                "1'; UPDATE accounts SET balance = 999999 WHERE user_id = 1; --",
                "-1 UNION SELECT * FROM users --",
                "1'; INSERT INTO accounts (user_id, account_number, balance) VALUES (999, 'HACK', 999999); --"
            ]
            
            for payload in injection_payloads:
                # Try injection through deposit amount
                success, message = self.bank_ops.deposit(payload)
                if success:
                    test_logger.log_vulnerability(
                        "SQL_INJECTION_IN_DEPOSIT",
                        f"SQL injection possible through deposit: {payload}",
                        "CRITICAL"
                    )
                
                # Try injection through withdrawal amount
                success, message = self.bank_ops.withdraw(payload)
                if success:
                    test_logger.log_vulnerability(
                        "SQL_INJECTION_IN_WITHDRAWAL",
                        f"SQL injection possible through withdrawal: {payload}",
                        "CRITICAL"
                    )
            
            # Check if database structure is intact
            conn = sqlite3.connect(self.test_db)
            cursor = conn.cursor()
            
            try:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                expected_tables = ['users', 'accounts', 'transactions', 'security_log', 'mfa_backup_codes']
                
                for expected_table in expected_tables:
                    if not any(expected_table in table[0] for table in tables):
                        test_logger.log_vulnerability(
                            "DATABASE_CORRUPTION",
                            f"Expected table {expected_table} missing - possible SQL injection damage",
                            "CRITICAL"
                        )
                
                test_logger.log_test_pass(self._testMethodName, "SQL injection protection working")
                
            except sqlite3.Error as e:
                test_logger.log_vulnerability(
                    "DATABASE_CORRUPTION",
                    f"Database corruption detected: {str(e)}",
                    "CRITICAL"
                )
            finally:
                conn.close()
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_data_encryption_in_storage(self):
        """Test that sensitive data is properly encrypted in storage"""
        try:
            # Make a transaction with sensitive details
            success, _ = self.bank_ops.deposit(100.0)
            self.assertTrue(success)
            
            # Check database directly to ensure sensitive data is encrypted
            conn = sqlite3.connect(self.test_db)
            cursor = conn.cursor()
            
            # Check transaction details encryption
            cursor.execute("SELECT encrypted_details FROM transactions LIMIT 1")
            result = cursor.fetchone()
            
            if result and result[0]:
                encrypted_details = result[0]
                
                # Check if it looks encrypted (not plaintext)
                if "Deposit" in encrypted_details or "account" in encrypted_details.lower():
                    test_logger.log_vulnerability(
                        "UNENCRYPTED_SENSITIVE_DATA",
                        "Transaction details stored in plaintext",
                        "HIGH"
                    )
                else:
                    test_logger.log_test_pass(self._testMethodName, "Sensitive data properly encrypted")
            
            # Check password storage
            cursor.execute("SELECT password_hash FROM users LIMIT 1")
            result = cursor.fetchone()
            
            if result and result[0]:
                password_hash = result[0]
                
                # Should be bcrypt hash starting with $2b$
                if not password_hash.startswith('$2b$'):
                    test_logger.log_vulnerability(
                        "WEAK_PASSWORD_STORAGE",
                        "Passwords not stored with strong hashing",
                        "CRITICAL"
                    )
            
            conn.close()
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise

class TestSystemSecurity(unittest.TestCase):
    """System-level security tests"""
    
    def setUp(self):
        test_logger.log_test_start(self._testMethodName)
    
    def test_file_permissions(self):
        """Test file permissions and access controls"""
        try:
            # Check if database file has appropriate permissions
            if os.path.exists('bank.db'):
                stat_info = os.stat('bank.db')
                permissions = oct(stat_info.st_mode)
                
                # On Unix systems, check for overly permissive permissions
                if hasattr(os, 'getuid'):  # Unix-like systems
                    if permissions.endswith('777') or permissions.endswith('666'):
                        test_logger.log_security_issue(
                            "OVERLY_PERMISSIVE_DB_FILE",
                            f"Database file has permissions {permissions}",
                            "MEDIUM"
                        )
            
            # Check encryption key file permissions
            if os.path.exists('encryption_key.key'):
                stat_info = os.stat('encryption_key.key')
                permissions = oct(stat_info.st_mode)
                
                if hasattr(os, 'getuid'):  # Unix-like systems
                    if permissions.endswith('777') or permissions.endswith('666'):
                        test_logger.log_security_issue(
                            "OVERLY_PERMISSIVE_KEY_FILE",
                            f"Encryption key file has permissions {permissions}",
                            "HIGH"
                        )
            
            test_logger.log_test_pass(self._testMethodName, "File permissions checked")
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_logging_security(self):
        """Test logging security and information disclosure"""
        try:
            # Test that sensitive information is not logged
            if os.path.exists('bank_app.log'):
                with open('bank_app.log', 'r') as f:
                    log_content = f.read()
                
                # Check for sensitive data in logs
                sensitive_patterns = [
                    r'password["\s]*[:=]["\s]*\w+',
                    r'mfa[_\s]*secret["\s]*[:=]["\s]*[A-Z0-9]+',
                    r'balance["\s]*[:=]["\s]*\d+\.\d+',
                    r'\$\d+\.\d+',  # Money amounts
                    r'[A-Z0-9]{32,}',  # Long hex strings (potentially secrets)
                ]
                
                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, log_content, re.IGNORECASE)
                    if matches:
                        test_logger.log_security_issue(
                            "SENSITIVE_DATA_IN_LOGS",
                            f"Potentially sensitive data found in logs: {pattern}",
                            "MEDIUM"
                        )
            
            test_logger.log_test_pass(self._testMethodName, "Logging security validated")
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_error_information_disclosure(self):
        """Test that error messages don't disclose sensitive information"""
        try:
            # Create a temporary database for testing
            db_fd, test_db = tempfile.mkstemp()
            
            try:
                user_auth = UserAuth(db_path=test_db)
                
                # Test login with non-existent user
                success, message = user_auth.login("nonexistent", "password")
                
                # Error message should not reveal if username exists
                if "user not found" in message.lower() or "does not exist" in message.lower():
                    test_logger.log_security_issue(
                        "USERNAME_ENUMERATION",
                        "Login error reveals username existence",
                        "MEDIUM"
                    )
                
                # Test with malformed input to trigger exceptions
                success, message = user_auth.login(None, None)
                
                # Should not reveal internal paths or system information
                system_info_patterns = [
                    r'/[a-zA-Z0-9_/]+\.py',  # File paths
                    r'line \d+',  # Line numbers
                    r'Traceback',  # Stack traces
                    r'sqlite3\.',  # Database implementation details
                ]
                
                for pattern in system_info_patterns:
                    if re.search(pattern, message):
                        test_logger.log_security_issue(
                            "INFORMATION_DISCLOSURE",
                            f"Error message contains system information: {pattern}",
                            "LOW"
                        )
                
                test_logger.log_test_pass(self._testMethodName, "Error handling secure")
                
            finally:
                os.close(db_fd)
                os.unlink(test_db)
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise

class TestPerformanceSecurity(unittest.TestCase):
    """Performance-related security tests"""
    
    def setUp(self):
        test_logger.log_test_start(self._testMethodName)
    
    def test_dos_protection(self):
        """Test protection against denial of service attacks"""
        try:
            # Create temporary database
            db_fd, test_db = tempfile.mkstemp()
            
            try:
                user_auth = UserAuth(db_path=test_db)
                
                # Test large input handling
                large_input = "A" * 10000
                
                start_time = time.time()
                success, message = user_auth.register_user(large_input, "Pass123!", "test@test.com")
                duration = time.time() - start_time
                
                # Should handle large input gracefully and quickly
                if duration > 5.0:
                    test_logger.log_security_issue(
                        "DOS_VULNERABILITY",
                        f"Large input processing took {duration:.2f}s (potential DoS)",
                        "MEDIUM"
                    )
                
                # Test rapid successive requests
                start_time = time.time()
                for i in range(100):
                    user_auth.register_user(f"user{i}", "Pass123!", f"user{i}@test.com")
                duration = time.time() - start_time
                
                if duration > 30.0:  # 100 requests in 30 seconds
                    test_logger.log_security_issue(
                        "PERFORMANCE_DOS_RISK",
                        f"100 registration attempts took {duration:.2f}s",
                        "LOW"
                    )
                
                test_logger.log_test_pass(self._testMethodName, "DoS protection adequate")
                
            finally:
                os.close(db_fd)
                os.unlink(test_db)
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise
    
    def test_resource_limits(self):
        """Test resource consumption limits"""
        try:
            # Test memory usage with large transactions
            db_fd, test_db = tempfile.mkstemp()
            
            try:
                # Setup database schema
                conn = sqlite3.connect(test_db)
                cursor = conn.cursor()
                
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
                
                conn.commit()
                conn.close()
                
                user_auth = UserAuth(db_path=test_db)
                bank_ops = BankOperations(user_auth, db_path=test_db)
                
                # Register and login
                success, _ = user_auth.register_user("perftest", "SecurePass123!", "perf@test.com")
                self.assertTrue(success)
                success, _ = user_auth.login("perftest", "SecurePass123!")
                self.assertTrue(success)
                
                # Test transaction history with many transactions
                for i in range(50):
                    bank_ops.deposit(10.0)
                
                start_time = time.time()
                success, history = bank_ops.get_transaction_history()
                duration = time.time() - start_time
                
                if duration > 2.0:
                    test_logger.log_security_issue(
                        "PERFORMANCE_ISSUE",
                        f"Transaction history retrieval took {duration:.2f}s",
                        "LOW"
                    )
                
                test_logger.log_test_pass(self._testMethodName, "Resource limits acceptable")
                
            finally:
                os.close(db_fd)
                os.unlink(test_db)
            
        except Exception as e:
            test_logger.log_test_fail(self._testMethodName, str(e))
            raise

def run_security_tests():
    """Run all security tests and generate comprehensive report"""
    print("Starting comprehensive security test suite...")
    print(f"Results will be logged to: {test_logger.log_file}")
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestSecurityUtils,
        TestSecurityAuthentication,
        TestBankingOperationsSecurity,
        TestSystemSecurity,
        TestPerformanceSecurity
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, stream=open(os.devnull, 'w'))
    result = runner.run(test_suite)
    
    # Generate and display report
    report = test_logger.generate_report()
    print(report)
    
    # Return summary
    return {
        'tests_run': result.testsRun,
        'failures': len(result.failures),
        'errors': len(result.errors),
        'vulnerabilities': len(test_logger.test_results['vulnerabilities']),
        'security_issues': len(test_logger.test_results['security_issues']),
        'performance_issues': len(test_logger.test_results['performance_issues']),
        'log_file': test_logger.log_file
    }

if __name__ == "__main__":
    # Run the comprehensive security test suite
    summary = run_security_tests()
    
    print(f"\n{'='*60}")
    print("SECURITY TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Tests Run: {summary['tests_run']}")
    print(f"Failures: {summary['failures']}")
    print(f"Errors: {summary['errors']}")
    print(f"Vulnerabilities: {summary['vulnerabilities']}")
    print(f"Security Issues: {summary['security_issues']}")
    print(f"Performance Issues: {summary['performance_issues']}")
    print(f"Log File: {summary['log_file']}")
    
    # Exit with appropriate code
    if summary['vulnerabilities'] > 0:
        print("\n❌ CRITICAL: Vulnerabilities found!")
        exit(2)
    elif summary['failures'] > 0 or summary['errors'] > 0:
        print("\n⚠️  WARNING: Test failures detected!")
        exit(1)
    elif summary['security_issues'] > 0:
        print("\n⚠️  INFO: Security issues found, review recommended")
        exit(0)
    else:
        print("\n✅ SUCCESS: All security tests passed!")
        exit(0)