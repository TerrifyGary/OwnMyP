# app.py
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
import sqlite3, base64, secrets, string
import bcrypt
from crypto_utils import gen_salt, derive_key, encrypt, decrypt
import init_db

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_RANDOM_SECRET"  # replace with a long random string
DB = "vault.db"

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('vault'))
    return redirect(url_for('login'))

# Register
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        salt = gen_salt()
        conn = get_db()
        conn.execute("INSERT INTO users (username,pwd_hash,kdf_salt) VALUES (?, ?, ?)",
                     (username, pwd_hash, base64.b64encode(salt)))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if not row: return "invalid user", 401
        if bcrypt.checkpw(password.encode(), row['pwd_hash']):
            salt = base64.b64decode(row['kdf_salt'])
            key = derive_key(password, salt)
            session['user_id'] = row['id']
            session['enc_key'] = base64.b64encode(key).decode()
            return redirect(url_for('vault'))
        return "invalid password", 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Vault page
@app.route('/vault')
def vault():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    rows = conn.execute("SELECT id, site, site_username FROM credentials WHERE user_id=?", (session['user_id'],)).fetchall()
    conn.close()
    return render_template('vault.html', items=rows)

# Add credential
@app.route('/create_credential', methods=['POST'])
def create_credential():
    if 'user_id' not in session: return redirect(url_for('login'))
    key = base64.b64decode(session['enc_key'])
    site = request.form['site']
    site_username = request.form['site_username']
    site_password = request.form['site_password']
    nonce, ct = encrypt(site_password.encode(), key)
    conn = get_db()
    conn.execute("INSERT INTO credentials (user_id, site, site_username, nonce, ciphertext) VALUES (?, ?, ?, ?, ?)",
                 (session['user_id'], site, site_username, base64.b64encode(nonce), base64.b64encode(ct)))
    conn.commit()
    conn.close()
    return redirect(url_for('vault'))

# Reveal credential
@app.route('/credential/<int:id>')
def show_credential(id):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    row = conn.execute("SELECT * FROM credentials WHERE id=? AND user_id=?", (id, session['user_id'])).fetchone()
    conn.close()
    if not row: return "not found", 404
    key = base64.b64decode(session['enc_key'])
    nonce = base64.b64decode(row['nonce'])
    ct = base64.b64decode(row['ciphertext'])
    plaintext = decrypt(nonce, ct, key).decode()
    return jsonify(site=row['site'], site_username=row['site_username'], site_password=plaintext)

# Delete credential
@app.route('/delete_credential/<int:id>', methods=['POST'])
def delete_credential(id):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    conn.execute("DELETE FROM credentials WHERE id=? AND user_id=?", (id, session['user_id']))
    conn.commit()
    conn.close()
    return '', 204 # No Content

# Generate random password
@app.route('/generate_password')
def generate_password():
    length = int(request.args.get('length', 16))
    level = int(request.args.get('level', 3)) # Default to level 3

    lowercase_chars = string.ascii_lowercase
    uppercase_chars = string.ascii_uppercase
    digit_chars = string.digits
    symbol_chars = string.punctuation

    alphabet = ""
    if level == 1:
        alphabet = lowercase_chars
    elif level == 2:
        alphabet = lowercase_chars + uppercase_chars + digit_chars
    elif level == 3:
        alphabet = lowercase_chars + uppercase_chars + digit_chars + symbol_chars
    else:
        # Default to level 3 if an invalid level is provided
        alphabet = lowercase_chars + uppercase_chars + digit_chars + symbol_chars

    if not alphabet: # Fallback in case alphabet is empty
        alphabet = string.ascii_letters + string.digits + string.punctuation

    pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
    return jsonify(password=pwd)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
