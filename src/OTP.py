import random
import smtplib
from email.message import EmailMessage

# Generate a 6-digit OTP
otp = ""
for i in range(6):
    otp += str(random.randint(0, 9))

print(otp)  # For testing purposes only, remove in production!

# Set up SMTP server
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()

from_mail = 'dennisswanhtet@gmail.com'
password = 'nbwo vuit ywbl shrf'  # Consider using environment variables for security
server.login(from_mail, password)

to_mail = input("Enter your email: ")

# Create email message
msg = EmailMessage()
msg['Subject'] = 'OTP Verification'
msg['From'] = from_mail
msg['To'] = to_mail
msg.set_content(f"Your OTP is: {otp}")

# Send email
server.send_message(msg)
server.quit()

print("Email sent")