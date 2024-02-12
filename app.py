
from flask import Flask, request, jsonify, redirect
import random, string
from flask_mail import Mail, Message


app = Flask(__name__)

class User:
    def __init__(self, user_id, username, email, password):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password = password
        
# Dummy database to store registered users
users = []
verification_tokens = {}

# def send_email(to, subject, body):
#     mail_settings = {
#         "MAIL_SERVER": "smtp.gmail.com",
#         "MAIL_PORT": 587,
#         "MAIL_USE_TLS": True,
#         "MAIL_USERNAME": "",
#         "MAIL_PASSWORD": ""
#     }

#     app.config.update(mail_settings)
#     mail = Mail(app)
#     msg = Message(subject, recipients=[to])
#     msg.body = body
#     mail.send(msg)

def send_verification_code(email, verification_code):
    print(f"Verification code sent to {email}: {verification_code}")
    
def generate_verification_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

def authenticate(username, password):
    # Check if the username and password match any user in the database
    for user in users:
        if user.username == username and user.password == password:
            return True
    return False

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Extract user details from request
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Validate input data
    if not username or not email or not password:
        return jsonify({'error': 'Please provide username, email, and password'})

    # Check if the user already exists
    if any(user['email'] == email for user in users):
        return jsonify({'error': 'User with this email already exists'})

    user_id = len(users) + 1
    # Create a new user
    new_user = User(user_id, username, email, password)
    users.append(new_user)
    
    # verification_token = generate_verification_token()
    # verification_tokens[verification_token] = new_user
    
    # verification_link = f"http://localhost:5000/verify/{verification_token}"
    # message_body = f"Please click on the following link to verify your email: {verification_link}"
    # send_email(email, "Email Verification", message_body)

    return redirect("/login")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return "This is the login page."
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Missing username or password"})
    
    user = authenticate(username, password)
    if user:
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"error": "Invalid username or password"})
    
@app.route('/forget_password', methods = ['POST'])
def forget_password():
    data = request.get_json()
    email = data.get('email')
    
    if any(user.email == email for user in users):
        # Generate a verification code
        verification_code = generate_verification_code()

        # Save verification code for this email
        verification_tokens[email] = verification_code

        # Send verification code to the user's email
        send_verification_code(email, verification_code)
        
        return jsonify({"message": "Verification code sent successfully"})
    else:
        return jsonify({"error": "Email not found in the database"})


if __name__ == '__main__':
    app.run(debug=True)
