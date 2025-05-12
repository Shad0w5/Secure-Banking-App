# Secure Banking Application

This is a simple Python-based banking application that demonstrates secure programming practices by Muhammad Abubakar student number: (L00172503)

## Features

- Secure account creation and authentication
- Multi-factor authentication
- Secure transaction processing
- Data encryption for sensitive information
- Comprehensive input validation
- Transaction integrity verification
- Detailed security logging

## Requirements

- Python 3.8+
- Required libraries are listed in `requirements.txt`

## Installation

1. Clone this repository
2. Install the required dependencies:

```
pip install -r requirements.txt
```

## Running the Application

```
python banking_app.py
```

## Running the Tests

```
python -m pytest test_banking_app.py -v
```
## Project Structure

- `banking_app.py` - Main application file
- `test_banking_app.py` - Unit tests
- `requirements.txt` - Required Python packages
- `README.md` - Project documentation

## Security Features Implemented

- Password hashing with bcrypt
- Multi-factor authentication with TOTP
- SQL injection prevention with parameterized queries
- Data encryption for sensitive information
- Transaction integrity verification with hash functions
- Comprehensive input validation
- Secure error handling and logging
- User access control

For more details on the security implementation, please see the security report document.