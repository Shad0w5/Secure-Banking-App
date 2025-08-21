# Secure Banking Application

A comprehensive Python-based banking application that demonstrates advanced secure programming practices and comprehensive security.

## Project Overview

This project implements a secure banking system with robust authentication, transaction management, and comprehensive security testing. The application follows industry best practices for financial software security, including multi-factor authentication, data encryption, and extensive vulnerability testing.

## Architecture

The project consists of two main components:

### 1. Main Application (`banking_app.py`)
- **Core Banking System**: Complete banking functionality with security-first design
- **User Authentication**: Multi-factor authentication with TOTP and backup codes
- **Transaction Management**: Secure deposit, withdrawal, and balance operations
- **Data Protection**: End-to-end encryption and secure data storage

### 2. Security Test Suite (`test_banking_app.py`)
- **Comprehensive Security Testing**: 50+ security tests covering all major vulnerabilities
- **Automated Vulnerability Detection**: SQL injection, XSS, authentication bypass testing
- **Performance Security Testing**: DoS protection and resource limit validation
- **Detailed Security Reporting**: JSON and text reports with vulnerability categorization

## Features

### Core Banking Features
- **Secure User Registration** - Strong password policies and input validation
- **Multi-Factor Authentication** - TOTP with QR codes and backup codes
- **Account Management** - View account details and transaction history
- **Secure Transactions** - Deposits and withdrawals with integrity verification
- **Transaction History** - Encrypted transaction logs with audit trail
- **Balance Management** - Real-time balance updates with fraud detection

### Security Features
- **Password Security** - bcrypt hashing with salt
- **Data Encryption** - Fernet symmetric encryption for sensitive data
- **SQL Injection Protection** - Parameterized queries throughout
- **Brute Force Protection** - Account lockout after failed attempts
- **Session Management** - Secure authentication state handling
- **Input Validation** - Comprehensive validation against all attack vectors
- **Transaction Integrity** - SHA-256 hash verification for all transactions
- **Audit Logging** - Detailed security event logging

### Testing & Quality Assurance
- **Unit Testing** - Complete test coverage for all components
- **Security Testing** - Vulnerability scanning and penetration testing
- **Performance Testing** - Load testing and resource usage validation
- **Integration Testing** - End-to-end workflow validation
- **Automated Reporting** - Detailed test reports with issue categorization

## Requirements

- **Python 3.8+**
- **SQLite3** (included with Python)
- **Dependencies**: See `requirements.txt`

## Installation

1. Git Clone the repository

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Optional: Install QR Code Support
```bash
# For QR code generation during MFA setup
pip install qrcode[pil]
```

## Running the Application

### Start the Banking Application
```bash
python banking_app.py
```

### Application Workflow
1. **Registration**: Create account with strong password and email
2. **MFA Setup**: Configure authenticator app using provided secret/QR code
3. **Login**: Username, password, and MFA code required
4. **Banking Operations**: Deposit, withdraw, view history, verify transactions
5. **Logout**: Secure session termination

## Running the Tests

### Run Security Test Suite
```bash
python test_banking_app.py
```

### Test Categories
- **Security Utils Testing**: Password hashing, encryption, input validation
- **Authentication Testing**: Login security, MFA validation, brute force protection
- **Banking Operations Testing**: Transaction security, authorization controls, race conditions
- **System Security Testing**: File permissions, logging security, error handling
- **Performance Security Testing**: DoS protection, resource limits

### Test Output Files
- `security_test_results_YYYYMMDD_HHMMSS.log` - Detailed test execution log
- `security_test_report_YYYYMMDD_HHMMSS.json` - Structured vulnerability report
- Console output with real-time test results and summary

## Project Structure

```
secure-banking-app/
├── banking_app.py              # Main application
├── test_banking_app.py         # Comprehensive security test suite
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── bank.db                     # SQLite database (created on first run)
├── encryption_key.key          # Encryption key (created on first run)
├── bank_app.log               # Application logs
└── security_test_results_*.log # Test execution logs
```

## Security Implementation Details

### Authentication Security
- **Password Policy**: Minimum 8 characters with uppercase, lowercase, numbers, and special characters
- **Password Storage**: bcrypt hashing with individual salts
- **MFA Implementation**: TOTP (Time-based One-Time Password) with backup codes
- **Account Lockout**: 5 failed attempts trigger account lockout
- **Session Management**: Secure authentication state with proper logout

### Data Protection
- **Encryption**: Fernet symmetric encryption for sensitive transaction details
- **Database Security**: Parameterized queries prevent SQL injection
- **Input Validation**: Regex-based validation with whitelist approach
- **Transaction Integrity**: SHA-256 hash verification for all financial transactions

### Audit & Monitoring
- **Security Logging**: All authentication and transaction events logged
- **Error Handling**: Secure error messages prevent information disclosure
- **Transaction History**: Encrypted audit trail for all account activities
- **Integrity Verification**: Hash-based transaction verification system

## Security Testing Results

The security test suite validates:

### Vulnerability Categories Tested
- **Injection Attacks**: SQL, XSS, Command injection protection
- **Authentication Bypass**: MFA bypass, session hijacking attempts
- **Authorization Issues**: Cross-user data access, privilege escalation
- **Data Exposure**: Sensitive data in logs, error messages, storage
- **Cryptographic Issues**: Weak encryption, predictable tokens
- **Performance Attacks**: DoS protection, resource exhaustion

### Test Coverage
- **50+ Individual Test Cases**
- **5 Major Test Categories**
- **Critical Vulnerability Detection**
- **Performance Impact Analysis**
- **Automated Report Generation**

## Usage Examples

### User Registration
```
Enter username: john_doe
Password requirements: at least 8 characters with uppercase, lowercase, numbers, and special characters
Enter password: [SecurePass123!]
Enter email: john@example.com

User registered successfully!
MFA Secret: JBSWY3DPEHPK3PXP
Backup codes: A1B2C3D4, E5F6G7H8, ...
```

### Secure Login
```
Enter username: john_doe
Enter password: [SecurePass123!]
MFA Code: 123456

Login successful.
```

### Banking Operations
```
--- Welcome, john_doe ---
1. View Account Details
2. Deposit
3. Withdraw
4. Transaction History
5. Verify Transaction
6. Logout
```

## Configuration Options

### Database Configuration
- SQLite database with automatic schema migration
- Encrypted sensitive data storage
- Transaction integrity verification

### Security Configuration
- Configurable password policies
- Adjustable account lockout thresholds
- Customizable MFA settings

### Logging Configuration
- Detailed security event logging
- Configurable log levels
- Secure log file handling

## Performance Considerations

- **Database Optimization**: Indexed queries and connection pooling
- **Encryption Overhead**: Minimal impact on transaction processing
- **Memory Management**: Efficient handling of large transaction histories
- **Concurrent Access**: Thread-safe transaction processing

## Security Best Practices Implemented

1. **Defense in Depth**: Multiple security layers throughout the application
2. **Principle of Least Privilege**: Users can only access their own data
3. **Secure by Default**: All operations require authentication and validation
4. **Input Validation**: All user input validated and sanitized
5. **Error Handling**: Secure error messages prevent information disclosure
6. **Audit Trail**: Complete logging of all security-relevant events

## Dependencies

### Core Dependencies
```
bcrypt>=4.0.0          # Password hashing
pyotp>=2.8.0           # Multi-factor authentication
cryptography>=41.0.0   # Data encryption
sqlite3                # Database (built-in)
```

### Optional Dependencies
```
qrcode[pil]>=7.4.0     # QR code generation for MFA setup
```


