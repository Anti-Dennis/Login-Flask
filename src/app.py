import sqlite3
import contextlib
import re
import random

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask, render_template, 
    request, session, redirect
)

from create_database import setup_database
from utils import login_required, set_session

#otp
import random
import smtplib
from email.message import EmailMessage



app = Flask(__name__)
app.secret_key = 'xpSm7p5bgJY8rNoBjGWiz5yjxM-NEBlW6SIBI62OkLc='

database = "users.db"
setup_database(name=database)


@app.route('/otp', methods=['GET', 'POST'])
def otp_verification():
    if request.method == 'GET':
        return render_template('otp.html')
    
    # Handle OTP verification logic here if method is POST
    otp = request.form.get('otp')
    # expected_otp = session.get('otp_code')

    if otp != otp_global:
        return render_template('otp.html', error='Incorrect OTP, please try again')

    # OTP verified, clear from session
    session.pop('otp_code', None)
    return redirect('/')


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

    # Set cookie for user session
    set_session(
        username=account[0], 
        email=account[2], 
        remember_me='remember-me' in request.form
    )
    
    return redirect('/')


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

    # Generate OTP and set in session
    otp_code = str(random.randint(100000, 999999))
    session['otp_code'] = otp_code
    # Ideally, send OTP via email or SMS to the user here

    # We can log the user in right away since no email verification
    set_session(username=username, email=email)
    otp(email)
    return redirect('/otp')



def otp(email):

    # Generate a 6-digit OTP
    global otp_global
    otp_global = ""
    for i in range(6):
        otp_global += str(random.randint(0, 9))

    print(otp_global)  # print for debug swam

    # Set up SMTP server
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()

    from_mail = 'dennisswanhtet@gmail.com'
    password = 'nbwo vuit ywbl shrf'  # Consider using environment variables for security
    server.login(from_mail, password)

    # to_mail = input("Enter your email: ")

    # Create email message
    msg = EmailMessage()
    msg['Subject'] = 'OTP Verification'
    msg['From'] = from_mail
    msg['To'] = email
    msg.set_content(f"Your OTP is: {otp_global}")

    # Send email
    server.send_message(msg)
    server.quit()

    print("Email sent")

if __name__ == '__main__':
    app.run(debug=True)
