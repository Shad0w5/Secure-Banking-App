# Secure Banking Application

This is a simple Python-based banking application that demonstrates secure programming practices.

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

For test coverage:

```
python -m pytest test_banking_app.py --cov=banking_app
```

## GitHub Integration with VS Code

### Setting up GitHub with VS Code

1. **Install Git**: If you don't already have Git installed, download and install it from [git-scm.com](https://git-scm.com/).

2. **Install VS Code**: Download and install Visual Studio Code from [code.visualstudio.com](https://code.visualstudio.com/).

3. **Configure Git in VS Code**:
   - Open VS Code
   - Open the terminal in VS Code (View > Terminal)
   - Configure your Git user name and email:
     ```
     git config --global user.name "Your Name"
     git config --global user.email "your.email@example.com"
     ```

4. **Clone the Repository**:
   - On GitHub, create a new repository
   - In VS Code, press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
   - Type "Git: Clone" and select it
   - Enter your repository URL
   - Choose a local folder to clone the repository to

5. **Authenticate with GitHub**:
   - VS Code will prompt you to sign in to GitHub
   - Follow the authentication steps (usually through a browser)

6. **Add Your Files to the Repository**:
   - Copy all the project files to the cloned repository folder
   - In VS Code, you'll see the files in the Source Control tab (the branch icon)
   - Stage your changes by clicking the '+' next to each file (or clicking the '+' next to "Changes" to stage all)
   - Enter a commit message and click the checkmark to commit
   - Click the "..." menu and select "Push" to push your changes to GitHub

7. **Enable GitHub Extensions** (optional but recommended):
   - Go to the Extensions tab in VS Code (the square icon)
   - Search for "GitHub Pull Requests and Issues"
   - Install the extension
   - This will make it easier to work with GitHub Pull Requests directly from VS Code

### Workflow for Making Changes

1. **Create a new branch** (good practice for each feature/fix):
   - In VS Code, click on the branch name in the bottom left
   - Select "Create new branch" and give it a name

2. **Make your changes** to the code

3. **Commit and push**:
   - Stage your changes
   - Enter a commit message
   - Click the checkmark to commit
   - Push your changes to GitHub

4. **Create a Pull Request** (if working collaboratively):
   - On GitHub, navigate to your repository
   - Click "Pull requests" > "New pull request"
   - Select your branch
   - Add description and create the pull request
   - After review, merge the pull request

## Sharing the Repository with Your Instructor

1. **Navigate to your repository** on GitHub

2. **Go to "Settings" > "Collaborators"**

3. **Add your instructor's GitHub username** as a collaborator
   - This will send them an invitation to access your repository
   - They will have access to view and pull your code

4. **Verify the instructor has access** before the submission deadline

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