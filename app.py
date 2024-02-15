import json
from flask import Flask, request, jsonify, redirect
import random, string
from flask_mail import Mail, Message
import re
import hashlib


app = Flask(__name__)


class User:
    def __init__(self, user_id, username, email, password):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password = password


def load_users_from_json():
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []


# Function to save users to JSON file
def save_users_to_json(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)


# Function to save activation OTP data to JSON file
def save_activation_otp_to_json(data):
    try:
        with open("activationotp.json", "r") as f:
            existing_data = json.load(f)
    except FileNotFoundError:
        existing_data = []

    # Check if user_id exists in the existing data
    for entry in existing_data:
        if entry["user_id"] == data["user_id"]:
            entry["verification_code"] = data["verification_code"]
            break
    else:
        existing_data.append(data)

    with open("activationotp.json", "w") as f:
        json.dump(existing_data, f, indent=4)


def save_activation_token_to_json(data):
    try:
        with open("activationtoken.json", "r") as f:
            activation_data = json.load(f)
    except FileNotFoundError:
        activation_data = []

    activation_data.append(data)

    with open("activationtoken.json", "w") as f:
        json.dump(activation_data, f, indent=4)


users = load_users_from_json()


# Function to send mails
def send_email(to, subject, body):
    mail_settings = {
        "MAIL_SERVER": "smtp.gmail.com",
        "MAIL_PORT": 587,
        "MAIL_USE_TLS": True,
        "MAIL_USERNAME": "",
        "MAIL_PASSWORD": "",
    }

    app.config.update(mail_settings)
    mail = Mail(app)
    msg = Message(subject, sender="dev1.wappnet@gmail.com", recipients=[to])
    msg.body = body
    mail.send(msg)


def send_verification_code(email, verification_code):
    print(f"Verification code sent to {email}: {verification_code}")


def generate_verification_token():
    return "".join(random.choices(string.ascii_letters + string.digits, k=6))


def generate_verification_code():
    return "".join(random.choices(string.digits, k=6))


# def authenticate(username, password):
#     for user in users:
#         if user['username'] == username and user['password'] == password:
#             return True
#     return False


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    # Extract user details from request
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    # Validate input data
    if not username or not email or not password:
        return jsonify({"error": "Please provide username, email, and password"})

    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"})

    # Check if the user with the email already exists
    if any(user["email"] == email for user in users):
        return jsonify({"error": "User with this email already exists"})

    # Check if the username is already taken
    if any(user["username"] == username for user in users):
        return jsonify({"error": "User with this username already exists"})

    user_id = len(users) + 1
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Create a new user
    new_user = User(user_id, username, email, hashed_password)
    users.append(vars(new_user))

    save_users_to_json(users)

    return jsonify({"message": f"User created successfully!"})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return "This is the login page."
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Validate input data
    if not username or not password:
        return jsonify({"message": "Missing username or password"})

    # user = authenticate(username, password)
    users = load_users_from_json()
    for user in users:
        if user["username"] == username:
            # Decode the hashed password from the JSON file
            hashed_password = user["password"]

            # Hash the provided password for comparison
            hashed_input_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

            # Compare the hashed passwords
            if hashed_password == hashed_input_password:
                return jsonify({"message": "Login successful"})
            else:
                return jsonify({"error": "Invalid password"})
            
    # If username not found, return error message
    return jsonify({"error": "Invalid username"})


@app.route("/forget_password", methods=["POST"])
def forget_password():

    data = request.get_json()
    email = data.get("email")

    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"})

    users = load_users_from_json()

    user = next((user for user in users if user["email"] == email), None)
    if user:
        # Generate a verification code
        verification_code = generate_verification_code()

        # Save user ID and verification code to JSON file
        activation_data = {
            "user_id": user["user_id"],
            "verification_code": verification_code,
        }
        save_activation_otp_to_json(activation_data)

        # Send verification code to the user's email
        send_email(
            email,
            "Forget Password Verification Code",
            f"Your verification code is: {verification_code}",
        )

        # Return success message
        return jsonify({"message": "Verification code sent successfully"})
    else:
        return jsonify({"error": "Email not found in the database"})


@app.route('/verify_otp', methods=['POST'])
def verify_and_generate_token():
    data = request.get_json()
    email = data.get('email')
    verification_code = data.get('verification_code')
    
    if not email:
        return jsonify({"error":"Please provide your email address."})
    
    if not verification_code:
        return jsonify({"error":"Please provide the OTP received on your email."})
        

    # Load users from JSON file
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
    except FileNotFoundError:
        return jsonify({"error": "User data not found"})

    # Find the user with the provided email
    user = next((user for user in users if user['email'] == email), None)
    if not user:
        return jsonify({"error": "User not found"})

    # Get the user_id
    user_id = user['user_id']

    # Load activation OTP data from JSON file
    try:
        with open('activationotp.json', 'r') as f:
            activation_data = json.load(f)
    except FileNotFoundError:
        return jsonify({"error": "Activation data not found"})

    # Check if the user_id and verification code match any entry in activation data
    for entry in activation_data:
        if entry['user_id'] == user_id and entry['verification_code'] == verification_code:
            # If match found, generate a verification token

            # Generate a verification token
            verification_token = generate_verification_token()

            # Load activation data from JSON file
            try:
                with open("activationtoken.json", "r") as f:
                    activation_data = json.load(f)
            except FileNotFoundError:
                activation_data = []

            # Check if the user_id already exists in activation data
            user_exists = False
            for entry in activation_data:
                if entry["user_id"] == user_id:
                    entry["verification_token"] = verification_token
                    user_exists = True
                    break

            # If user_id doesn't exist in activation data, append a new entry
            if not user_exists:
                activation_data.append({"user_id": user_id, "verification_token": verification_token})

            # Save updated activation data back to JSON file
            with open("activationtoken.json", "w") as f:
                json.dump(activation_data, f, indent=4)

            # Print the token
            print(f"Verification token: {verification_token}")

            return jsonify({"message": "Token generated successfully", "verification_token": verification_token})

    # If no match found, return error message
    return jsonify({"error": "Incorrect verification code or user ID"})


@app.route("/reset_password", methods=["POST"])
def reset_password():
    data = request.get_json()
    # email = data.get("email")
    token = data.get("verification_token")
    new_password = data.get("new_password")

    # Load activation token data from JSON file
    try:
        with open("activationtoken.json", "r") as f:
            activation_data = json.load(f)
    except FileNotFoundError:
        return jsonify({"error": "Activation token database not found"})

    # Check if the token matches any entry in activation data
    token_matched = False
    user_id = None
    for entry in activation_data:
        if entry["verification_token"] == token:
            token_matched = True
            user_id = entry["user_id"]
            break

    if not token_matched or not user_id:
        return jsonify({"error": "Invalid or expired token"})

    # Load users from JSON file
    try:
        with open("users.json", "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        return jsonify({"error": "User database not found"})

    # Find the user with the provided user_id
    user = next((user for user in users if user["user_id"] == user_id), None)
    if not user:
        return jsonify({"error": "User not found"})

    # Hash the new password
    hashed_new_password = hashlib.sha256(new_password.encode('utf-8')).hexdigest()

    # Update the password for the user
    user["password"] = hashed_new_password

    # Save the updated users back to the JSON file
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

    # Empty the activation token data
    with open("activationtoken.json", "w") as f:
        json.dump([], f)

    return jsonify({"message": "Password reset successfully"})


if __name__ == "__main__":
    app.run(debug=True)
