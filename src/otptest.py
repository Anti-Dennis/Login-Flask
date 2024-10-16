from flask import Flask, render_template, request, redirect, url_for, session, flash
import random
import smtplib  # For sending OTP via email (optional)
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key for session management

# Simulated database for user OTPs (in real use, replace with an actual database)
user_data = {}

# Function to generate a random OTP
def generate_otp():
    return random.randint(100000, 999999)

# Route for the registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Generate OTP and save to session (or database)
        otp = generate_otp()
        session['otp'] = otp
        session['username'] = username  # Save user data temporarily for demo purposes
        
        # Optionally, send OTP to the user's email
        # send_otp_email(email, otp)  # Uncomment this if email sending is needed
        
        # Redirect to OTP page
        return redirect(url_for('otp_verification'))
    
    return render_template('register.html')

# Route for the OTP page
@app.route('/otp', methods=['GET', 'POST'])
def otp_verification():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        saved_otp = str(session.get('otp'))  # Retrieve the OTP saved during registration
        
        if entered_otp == saved_otp:
            flash('OTP Verified Successfully!', 'success')
            # OTP verified; redirect to the index or welcome page
            return redirect(url_for('index'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
    
    return render_template('otp.html')

# Route for the main/index page
@app.route('/')
def index():
    username = session.get('username')
    return render_template('index.html', username=username)

# Function to send OTP via email (optional)
def send_otp_email(recipient_email, otp):
    sender_email = 'your_email@example.com'
    sender_password = 'your_email_password'
    subject = 'Your OTP Code'
    body = f'Your OTP code is: {otp}'
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = recipient_email
    
    try:
        with smtplib.SMTP('smtp.example.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
    except Exception as e:
        print(f"Error sending email: {e}")

if __name__ == '__main__':
    app.run(debug=True)
