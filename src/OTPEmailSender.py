import sqlite3
import contextlib
import re
import secrets
import smtplib
from email.message import EmailMessage
import time
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask, render_template, 
    request, session, redirect
)

from create_database import setup_database
from utils import login_required, set_session


app = Flask(__name__)
app.secret_key = 'xpSm7p5bgJY8rNoBjGWiz5yjxM-NEBlW6SIBI62OkLc='

database = "users.db"
setup_database(name=database)

otp_store = {}

@app.route('/')
@login_required
def index():
    print(f'User data: {session}')
    return render_template('index.html', username=session.get('username'))


@app.route('/logout')
def logout():
    session.clear()
    session.permanent = False
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    # Set data to variables
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Attempt to query associated user data
    query = 'select username, password, email from users where username = :username'

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account: 
        return render_template('login.html', error='Username does not exist')

    # Verify password
    try:
        ph = PasswordHasher()
        ph.verify(account[1], password)
    except VerifyMismatchError:
        return render_template('login.html', error='Incorrect password')

    # Check if password hash needs to be updated
    if ph.check_needs_rehash(account[1]):
        query = 'update users set password = :password where username = :username'
        params = {'password': ph.hash(password), 'username': account[0]}

        with contextlib.closing(sqlite3.connect(database)) as conn:
            with conn:
                conn.execute(query, params)

    # Generate OTP
    otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
    otp_store[username] = {'otp': otp, 'timestamp': time.time()}

    # Send OTP via email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()

        from_mail = os.getenv('EMAIL_USER', 'dennisswanhtet@gmail.com')
        email_password = os.getenv('EMAIL_PASS', 'nbwo vuit ywbl shrf')
        server.login(from_mail, email_password)

        to_mail = account[2]

        msg = EmailMessage()
        msg['Subject'] = 'OTP Verification'
        msg['From'] = from_mail
        msg['To'] = to_mail
        msg.set_content(f"Your OTP is: {otp}")

        server.send_message(msg)
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")
        return render_template('login.html', error='Failed to send OTP. Please try again later.')
    finally:
        server.quit()

    return redirect(f'/verify?username={username}')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    username = request.args.get('username')
    if request.method == 'GET':
        return render_template('verify.html', username=username)

    user_otp = request.form.get('otp')
    if username not in otp_store:
        return render_template('verify.html', username=username, error='OTP not found. Please try again.')

    otp_data = otp_store[username]
    otp_valid_time = 300  # 5 minutes

    # Verify OTP
    if time.time() - otp_data['timestamp'] > otp_valid_time:
        return render_template('verify.html', username=username, error='OTP expired. Please request a new OTP.')

    if user_otp == otp_data['otp']:
        set_session(username=username, email=request.args.get('email'))
        otp_store.pop(username)  # Remove OTP after successful verification
        return redirect('/')
    else:
        return render_template('verify.html', username=username, error='Invalid OTP. Please try again.')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    # Store data to variables 
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')
    username = request.form.get('username')
    email = request.form.get('email')

    # Verify data
    if len(password) < 8:
        return render_template('register.html', error='Your password must be 8 or more characters')
    if not re.search(r'[A-Z]', password):
        return render_template('register.html', error='Your password must contain at least one uppercase letter')
    if not re.search(r'[a-z]', password):
        return render_template('register.html', error='Your password must contain at least one lowercase letter')
    if not re.search(r'\d', password):
        return render_template('register.html', error='Your password must contain at least one number')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return render_template('register.html', error='Your password must contain at least one special character')
    if password != confirm_password:
        return render_template('register.html', error='Passwords do not match')
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return render_template('register.html', error='Username must only be letters and numbers')
    if not 3 < len(username) < 26:
        return render_template('register.html', error='Username must be between 4 and 25 characters')

    query = 'select username from users where username = :username;'
    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            result = conn.execute(query, {'username': username}).fetchone()
    if result:
        return render_template('register.html', error='Username already exists')

    # Create password hash
    pw = PasswordHasher()
    hashed_password = pw.hash(password)

    query = 'insert into users(username, password, email) values (:username, :password, :email);'
    params = {
        'username': username,
        'password': hashed_password,
        'email': email
    }

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            result = conn.execute(query, params)

    # We can log the user in right away since no email verification
    set_session(username=username, email=email)
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)