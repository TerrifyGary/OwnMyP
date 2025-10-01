# OwnNote - A Secure Password Vault

OwnNote is a Flask-based web application designed to securely store and manage your online credentials. It provides a user-friendly interface for registering, logging in, adding new credentials, viewing existing ones, and generating strong, random passwords.

## Features

- **User Registration & Authentication**: Secure user registration and login system.
- **Secure Credential Storage**: Encrypts and stores website usernames and passwords.
- **Credential Management**: Add, view, and delete stored credentials.
- **Password Generation**: Generate strong, customizable random passwords.
- **Session Management**: Secure user sessions.

## Setup and Installation

To get OwnNote up and running on your local machine, follow these steps:

### Prerequisites

- Python 3.x
- pip (Python package installer)

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/TerrifyGary/OwnMyP.git
   cd OwnMyP
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install Flask bcrypt
   ```
   *(Note: `sqlite3` and `base64` are typically built-in with Python.)*

4. **Initialize the database:**
   ```bash
   python init_db.py
   ```

5. **Run the application:**
   ```bash
   python app.py
   ```

6. **Run the ngrok**
    ```bash
    ngrok http 8080
    ```

The application will be accessible at `http://0.0.0.0:8080` (or `http://localhost:8080`).

## Usage

1. **Register**: Navigate to the `/register` page to create a new account.
2. **Login**: Use your registered username and password to log in.
3. **Vault**: After logging in, you will be redirected to your personal vault where you can:
   - **Add New Credentials**: Enter the site, username, and password for a new entry.
   - **View Credentials**: Click on an entry to reveal the stored password.
   - **Delete Credentials**: Remove an entry from your vault.
4. **Generate Password**: Use the password generation feature to create strong passwords.

## Technologies Used

- **Backend**: Flask (Python web framework)
- **Database**: SQLite3
- **Password Hashing**: bcrypt
- **Encryption**: Custom utility (`crypto_utils.py`) using `secrets` and `base64`

## Security Considerations

- **Secret Key**: Remember to change `app.secret_key = "CHANGE_THIS_RANDOM_SECRET"` in `app.py` to a long, randomly generated string for production environments.
- **KDF Salt**: Key Derivation Function (KDF) salt is used to derive encryption keys from user passwords, adding an extra layer of security.
- **Password Hashing**: User login passwords are hashed using `bcrypt` before storage.
- **Credential Encryption**: Stored site passwords are encrypted using a key derived from the user's login password.
