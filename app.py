from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message  # Import Flask-Mail
import secrets
import traceback
import datetime
from datetime import datetime, timedelta
from imgurpython import ImgurClient 
import os
from werkzeug.utils import secure_filename

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
app.config['MAIL_DEFAULT_SENDER'] = 'Masri'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image file extensions

db=SQLAlchemy(app)
bcrypt = Bcrypt(app) 
mail = Mail(app)



class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    profilepic = db.Column(db.String(120))
    admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False , unique=True)
    category = db.Column(db.String(50), nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    image = db.Column(db.String(120))
    description = db.Column(db.Text, nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)



class ResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def is_valid(self):
        expiration_time = self.created_at + timedelta(hours=3)
        return datetime.utcnow() <= expiration_time



# Define your Imgur client ID and secret
IMGUR_CLIENT_ID = 'f4b1b04c693195a'
IMGUR_CLIENT_SECRET = '81d18bcbe5d1ab6068bbd993b193f2946e9ccbab'

imgur_client = ImgurClient(IMGUR_CLIENT_ID, IMGUR_CLIENT_SECRET)




# //////////create_post/////////////////

@app.route('/post', methods=['POST'])
def create_post():
    data = request.form

    # Check if the user exists
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    imgur_link = None

    # Check if an image file is provided in the request
    if 'file' in request.files:
        image_file = request.files['file']
        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
            imgur_response = upload_image_to_imgur(image_path)

            if imgur_response:
                imgur_link = imgur_response['link']
            else:
                return jsonify({'message': 'Image upload to Imgur failed'}), 500
        else:
            return jsonify({'message': 'File upload failed. Allowed file extensions: png, jpg, jpeg, gif'}), 400

    # Generate the current timestamp
    current_time = datetime.utcnow()

    new_post = Post(
        title=data['title'],
        category=data['category'],
        time=current_time,
        image=imgur_link,  # Store the Imgur link in the database
        description=data['description'],
        user_id=user.id
    )
    db.session.add(new_post)
    db.session.commit()

    return jsonify({'message': 'Post created successfully'}), 201

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def upload_image_to_imgur(image_file):
    try:
        response = imgur_client.upload_from_path(image_file)
        return response
    except Exception as e:
        print(f'Error uploading image to Imgur: {str(e)}')
        return None



@app.route('/post/edit/<int:post_id>', methods=['PUT'])
def edit_post(post_id):
    # Check if the post exists
    post = Post.query.get(post_id)

    if not post:
        return jsonify({'message': 'Post not found'}), 404

    # Check if the user is authorized to edit the post
    user_email = request.form.get('email')  # You might need to adapt this based on your request format
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Check if the user is the author of the post or has admin privileges
    if post.user_id != user.id and not user.admin:
        return jsonify({'message': 'Unauthorized to edit this post'}), 403

    # Check if an image file is provided in the request
    imgur_link = post.image
    if 'file' in request.files:
        image_file = request.files['file']
        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
            imgur_response = upload_image_to_imgur(image_path)

            if imgur_response:
                imgur_link = imgur_response['link']
            else:
                return jsonify({'message': 'Image upload to Imgur failed'}), 500
        else:
            return jsonify({'message': 'File upload failed. Allowed file extensions: png, jpg, jpeg, gif'}), 400

    # Update the post's attributes
    post.title = request.form.get('title', post.title)
    post.category = request.form.get('category', post.category)
    post.description = request.form.get('description', post.description)
    post.image = imgur_link

    db.session.commit()

    return jsonify({'message': 'Post edited successfully'}), 200



@app.route('/post/delete/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    # Check if the post exists
    post = Post.query.get(post_id)

    if not post:
        return jsonify({'message': 'Post not found'}), 404

    user_id = request.json.get('user_id')

    if not user_id:
        return jsonify({'message': 'User ID is required in the request'}), 400

    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    if post.user_id != user.id:
        return jsonify({'message': 'Unauthorized to delete this post'}), 403

    # Delete associated comments first
    Comment.query.filter_by(post_id=post.id).delete()

    # Remove the post from the database
    db.session.delete(post)
    db.session.commit()

    return jsonify({'message': 'Post and associated comments deleted successfully'})



@app.route('/posts', methods=['GET'])
def get_posts():
    # Query all posts from the database
    posts = Post.query.all()

    # Create a list to store post data
    post_list = []

    # Iterate through the posts and append their data to the list
    for post in posts:
        post_data = {
            'id': post.id,
            'title': post.title,
            'category': post.category,
            'time': post.time.strftime('%Y-%m-%d %H:%M:%S'),  # Format timestamp as a string
            'image': post.image,
            'description': post.description,
            'user_id': post.user_id,
        }
        post_list.append(post_data)

    # Return the list of posts as JSON
    return jsonify({'posts': post_list})


# ///////////endpost/////////////





# /////////user registration////////////
 
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

# //////////endregister///////////////


# /////////////reset_password//////////

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

    # Send the reset token to the user's email with HTML and CSS styling
    reset_link = f"http://localhost:5000/reset_password?token={reset_token}"  # Update URL accordingly

    # Create an HTML email with CSS styling
    msg = Message('Password Reset', recipients=[email])
    msg.html = f"""
     <html>
      <head>
        <style>
            /* Add your CSS styling here */
            body {{
                font-family: Arial, sans-serif;
                background-color: #f5f5f5;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }}
            .content {{
                background-color: #ffffff;
                padding: 20px;
                border-radius: 5px;
            }}
            .button {{
                display: inline-block;
                background-color: #007BFF;
                color: #fff;
                padding: 12px 24px;
                border-radius: 5px;
                text-decoration: none;
                font-weight: bold;
            }}
            .button:hover {{
                background-color: #0056b3;
            }}
            .message {{
                color: #555;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="content">
                <h2>Password Reset</h2>
                <p class="message">You've requested a password reset. Click the button below to reset your password:</p>
                <a class="button" href="{reset_link}">Reset Password</a>
                <p class="message" style="color: white;">Please note that this reset link will expire after 3 hours.</p>
            </div>
        </div>
     </body>
    </html>
    """
 


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

    if not reset_token_entry.is_valid():
        return jsonify({'message': 'Reset token has expired'}), 400

    user = User.query.get(reset_token_entry.user_id)

    # Update the user's password with the new password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password

    # Remove the used reset token from the database
    db.session.delete(reset_token_entry)
    db.session.commit()

    return jsonify({'message': 'Password reset successful'})

# /////////////end reset_password//////////



# //////////comment////////////////

from datetime import datetime

@app.route('/comment', methods=['POST'])
def create_comment():
    data = request.get_json()

    user_id = data.get('user_id')
    post_id = data.get('post_id')
    text = data.get('text')

    if not all([user_id, post_id, text]):
        return jsonify({'message': 'Missing required data in the request'}), 400

    user = User.query.get(user_id)
    post = Post.query.get(post_id)

    if not user or not post:
        return jsonify({'message': 'User or Post not found'}), 404

    current_time = datetime.utcnow()  # Get the current timestamp

    new_comment = Comment(
        text=text,
        time=current_time,  # Set the current timestamp
        user_id=user.id,
        post_id=post.id
    )

    db.session.add(new_comment)
    db.session.commit()

    return jsonify({'message': 'Comment created successfully'}), 201



@app.route('/post/<int:post_id>/comments', methods=['GET'])
def get_comments_for_post(post_id):
    # Check if the post exists
    post = Post.query.get(post_id)

    if not post:
        return jsonify({'message': 'Post not found'}), 404

    # Retrieve comments for the specified post
    comments = Comment.query.filter_by(post_id=post.id).all()

    # Serialize comments to JSON
    comments_data = [
        {
            'id': comment.id,
            'text': comment.text,
            'time': comment.time.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': comment.user_id
        }
        for comment in comments
    ]

    return jsonify({'comments': comments_data})

@app.route('/comment/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    data = request.get_json()

    comment = Comment.query.get(comment_id)

    if not comment:
        return jsonify({'message': 'Comment not found'}), 404

    if comment.user_id != data['user_id']:
        return jsonify({'message': 'Unauthorized to delete this comment'}), 403

    db.session.delete(comment)
    db.session.commit()

    return jsonify({'message': 'Comment deleted successfully'})



# //////////////endcomment///////////

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
