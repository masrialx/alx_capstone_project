from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message  # Import Flask-Mail
import uuid
import secrets
import traceback
import datetime

app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
app.config['SECRET_KEY']='72d630c0cef6c01bff062d80'

app.app_context().push()
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'masrialemu404@gmail.com'
app.config['MAIL_PASSWORD'] = 'edfk ycdz zyeh ewxt'
app.config['MAIL_DEFAULT_SENDER'] = 'masreshalemu@gmail.com'

db=SQLAlchemy(app)
bcrypt = Bcrypt(app) 
mail = Mail(app)


class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    # public_id = db.Column(db.String(80), nullable=True,unique=True)
    admin = db.Column(db.Boolean, default=False)
    profilepic = db.Column(db.String(120))

class ResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), nullable=False)


# Endpoint for user registration
# Endpoint for user registration
@app.route('/check_token', methods=['POST'])
def check_token():
    data = request.get_json()
    token_to_check = data.get('token')

    # Query the ResetToken table for the provided token
    reset_token_entry = db.session.query(ResetToken).filter_by(token=token_to_check).first()
    
    if reset_token_entry:
        return jsonify({'message': 'Token exists in the database'})
    else:
        return jsonify({'message': 'Token does not exist in the database'})


@app.route('/emailsend', methods=['POST'])
def send_email():
    data = request.get_json()
    subject = data.get('subject')
    recipients = data.get('recipients')
    message_body = data.get('message_body')

    msg = Message(subject, recipients=recipients)
    msg.body = message_body

    try:
        mail.send(msg)  # Send the email
        return jsonify({'message': 'Email sent successfully'})
    except Exception as e:
        # Log the error
        traceback.print_exc()  # This will print the exception traceback
        return jsonify({'message': f'Email not sent: {str(e)}'}), 500


@app.route('/users/<int:user_id>', methods=['GET'])
def find_user_by_id(user_id):
    user = User.query.get(user_id)
    if user:
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'name': user.name,
            # 'public_id': user.public_id,
            'admin': user.admin,
            'password': user.password,
            'profilepic': user.profilepic
            # Exclude 'password' from the user data
        }
        return jsonify({'user': user_data})
    else:
        return jsonify({'message': 'User not found'}), 404


@app.route('/users', methods=['GET'])
def get_all_users():
    try:
        # Query all users from the User table
        users = User.query.all()

        # Create a list to store user data
        user_list = []

        # Iterate through the users and append their data to the list
        for user in users:
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'name': user.name,
                # 'public_id': user.public_id,
                'admin': user.admin,
                'profilepic': user.profilepic,
                'password': user.password,
            }
            user_list.append(user_data)

        # Return the list of users as JSON
        return jsonify({'users': user_list})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Check if the provided email and password match any user in the database
    user = User.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Password is correct, proceed with authentication
        # You can generate a JWT token or set a session here
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'message': 'Invalid email or password'}), 401

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    new_public_id = str(uuid.uuid4())
    
    # Check if the username or email already exists
    existing_user = User.query.filter_by(username=data['username']).first() or User.query.filter_by(email=data['email']).first()
    
    if existing_user:
        return jsonify({'message': 'Username or email already exists'}), 400

    # Create a new user
    new_user = User(
        # public_id=new_public_id,
        username=data['username'],
        email=data['email'],
        name=data['name'],
        profilepic=data.get('profilepic')  # Set profilepic if provided, otherwise it will be None
    )
    
    # Hash the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user.password = hashed_password

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/request_reset_password', methods=['POST'])
def request_reset_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'Email not found'}), 400

    # Generate a unique reset token
    reset_token = secrets.token_urlsafe(32)

    # Store the reset token in the database
    reset_token_entry = ResetToken(user_id=user.id, token=reset_token)
    db.session.add(reset_token_entry)
    db.session.commit()

    # Send the reset token to the user's email
    reset_link = f"http://localhost:5000/reset_password?token={reset_token}"  # Update URL accordingly
    msg = Message('Password Reset', recipients=[email])
    msg.body = f"Click the following link to reset your password: {reset_link}"

    try:
        mail.send(msg)  # Send the email
        return jsonify({'message': 'Password reset email sent'})
    except Exception as e:
        # Log the error
        traceback.print_exc()
        return jsonify({'message': f'Email not sent: {str(e)}'}), 500

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    reset_token_entry = ResetToken.query.filter_by(token=token).first()
    if not reset_token_entry:
        return jsonify({'message': 'Invalid reset token'}), 400

    user = User.query.get(reset_token_entry.user_id)

    # Update the user's password with the new password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password

    # Remove the used reset token from the database
    db.session.delete(reset_token_entry)
    db.session.commit()

    return jsonify({'message': 'Password reset successful'})


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
