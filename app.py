from flask import Flask, request, flash  # Flask framework for web application and request handling
from flask_sqlalchemy import SQLAlchemy  # SQL database integration for Flask
from flask_bcrypt import Bcrypt  # Password hashing for security
from flask_mail import Mail, Message  # Integration for sending email using Flask-Mail
import secrets  # Generate secure tokens or random strings
import traceback  # Handling and logging of exceptions and errors
from datetime import datetime, timedelta  # Date and time manipulation
from imgurpython import ImgurClient  # Imgur API client for image uploading
import os  # Operating system-related operations
from werkzeug.utils import secure_filename  # Secure filename handling for file uploads
from flask_jwt_extended import JWTManager, create_access_token  # JWT authentication for Flask
from flask import redirect, url_for, render_template  # Routing and HTML rendering in Flask
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user  # User authentication and session management in Flask
from sqlalchemy.exc import IntegrityError, SQLAlchemyError  # Handling database-related errors
import requests  # Making HTTP requests
import time  # Handling time-related operations
import hashlib


# Create a Flask web application instance with the name of the current module
app = Flask(__name__)

# The variable 'app' is now an instance of the Flask web application,
# which can be used to define routes, configure settings, and more.

# Configure the database URI for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'

# Configure the secret key for the application (for security)
app.config['SECRET_KEY'] = '72d630c0cef6c01bff062d80'

# Create an application context
app.app_context().push()

# Configure email settings for sending emails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'masrialemu404@gmail.com'
app.config['MAIL_PASSWORD'] = 'fctx lfch uhff jgmt'
app.config['MAIL_DEFAULT_SENDER'] = 'Masri'

# Configure settings for file uploads
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image file extensions

# Configure JWT (JSON Web Token) settings for authentication
app.config['JWT_SECRET_KEY'] = '72d630c0cef6c01bff062d80'  # Replace with a strong secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Set token expiration time (1 hour)

# Define your Imgur client ID and secret
IMGUR_CLIENT_ID = 'f4b1b04c693195a'
IMGUR_CLIENT_SECRET = '81d18bcbe5d1ab6068bbd993b193f2946e9ccbab'

imgur_client = ImgurClient(IMGUR_CLIENT_ID, IMGUR_CLIENT_SECRET)



# Initialize JWT (JSON Web Token) for authentication using the Flask app
jwt = JWTManager(app)

# Initialize SQLAlchemy for database operations using the Flask app
db = SQLAlchemy(app)

# Initialize Bcrypt for password hashing using the Flask app
bcrypt = Bcrypt(app)

# Initialize Flask-Mail for sending emails using the Flask app
mail = Mail(app)

# Initialize Flask-Login for user session management using the Flask app
login_manager = LoginManager(app)
login_manager.login_view = "login"



# Define the User model, which represents user information
class User(UserMixin, db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    profilepic = db.Column(db.String(120))
    admin = db.Column(db.Boolean, default=False)
    # Define relationships with Post and Comment models
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

# Define the Post model, representing posts or articles
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False, unique=True)
    category = db.Column(db.String(50), nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    image = db.Column(db.String(120))
    description = db.Column(db.Text, nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Define a relationship with the Comment model
    comments = db.relationship('Comment', backref='post', lazy=True)

# Define the Comment model for user comments on posts
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

# Define the ResetToken model for password reset tokens
class ResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Check if the reset token is still valid
    def is_valid(self):
        expiration_time = self.created_at + timedelta(hours=3)
        return datetime.utcnow() <= expiration_time

# Helper function to load a user based on the user_id
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    success = False  # Initialize a flag to track the success status

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        # Check if title and description are provided
        if not title:
            flash('Title is required', 'error')
        if not description:
            flash('Description is required', 'error')

        if not title or not description:
            return render_template('post.html')

        category = request.form['category']
        user_id = current_user.id  # Get the current user's ID

        imgbb_image_url = None  # Initialize imgbb_image_url to None

        if 'file' in request.files:
            image_file = request.files['file']
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)

                imgbb_image_url = upload_image_to_imgbb(image_path)

        current_time = datetime.utcnow()

        new_post = Post(
            title=title,
            category=category,
            description=description,
            user_id=user_id,
            time=current_time,
            image=imgbb_image_url  # Assign the ImgBB image link if it exists
        )

        db.session.add(new_post)

        try:
            db.session.commit()
            flash('Post created successfully', 'success')
            success = True  # Set the success flag to True
        except IntegrityError as e:
            db.session.rollback()
            flash('Failed to create the post. This description is already in use.', 'error')
        except Exception as e:
            db.session.rollback()
            flash('Failed to create the post. Error: ' + str(e), 'error')

    if success:  # Redirect to the home page only when the post is successfully created
        return redirect(url_for('home'))

    return render_template('post.html')

# Function to check if the uploaded file has an allowed file extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Function to upload an image to ImgBB and return the image URL
def upload_image_to_imgbb(image_file_path):
    try:
        # Define the ImgBB API endpoint for image upload
        imgbb_upload_url = 'https://api.imgbb.com/1/upload'

        # Set up the parameters for the ImgBB API request
        params = {
            'key': 'bb3c04e726776d171fb92035dfb747cf'  # Replace with your actual ImgBB API key
        }

        # Send the POST request to upload the image to ImgBB
        response = requests.post(imgbb_upload_url, params=params, files={'image': open(image_file_path, 'rb')})

        if response.status_code == 200:
            imgbb_image_url = response.json()['data']['url']
            return imgbb_image_url
        else:
            return None
    except Exception as e:
        print(f'Error uploading image to ImgBB: {str(e)}')
        return None


from flask import render_template, request, redirect, url_for
from flask_login import current_user  # Import current_user

@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    try:
        # Get the selected category from the request
        selected_category = request.args.get('category', 'All')

        # Get the search query from the request
        search_query = request.args.get('search', '')

        # Query posts based on the selected category
        if selected_category == 'All':
            posts = db.session.query(Post, User).join(User).all()
        else:
            posts = db.session.query(Post, User).join(User).filter(Post.category == selected_category).all()

        # Filter posts containing the search term in the title
        if search_query:
            posts = [post for post in posts if search_query.lower() in post.Post.title.lower()]

        # Create a list to store post data
        post_list = []

        # Iterate through the posts and append their data to the list
        for post, user in posts:
            post_data = {
                'id': post.id,
                'title': post.title,
                'category': post.category,
                'time': post.time.strftime('%Y-%m-%d %H:%M:%S'),  # Format timestamp as a string
                'image': post.image,
                'description': post.description,
                'user_id': post.user_id,
                'username': user.username,  # Include the username from the User model
                'profile_pic': user.profilepic,  # Include the profile picture from the User model
            }

            # Count the number of comments for each post
            comment_count = Comment.query.filter(Comment.post_id == post_data['id']).count()
            post_data['comment_count'] = comment_count

            post_list.append(post_data)

        # Reverse the order of post_list to display new posts at the beginning
        post_list = post_list[::-1]

        # Check if a user is logged in
        if current_user.is_authenticated:
            user_profile = {
                'username': current_user.username,
                'profile_pic': current_user.profilepic,
                # Include other user profile information as needed
            }
        else:
            user_profile = None

        # Pass the post data, selected category, search query, and user profile to the 'home.html' template
        return render_template('home.html', posts=post_list, selected_category=selected_category, search_query=search_query, user_profile=user_profile)
    except SQLAlchemyError as e:
        # Handle database-related errors
        db.session.rollback()
        error_message = 'An error occurred while retrieving data from the database: ' + str(e)
        flash(error_message, 'error')
        return render_template('home.html', posts=[], selected_category='All', search_query='')

    except Exception as e:
        # Handle other unexpected errors
        error_message = 'An unexpected error occurred: ' + str(e)
        flash(error_message, 'error')
        return render_template('home.html', posts=[], selected_category='All', search_query='')


# @app.route('/', methods=['GET', 'POST'])
# @app.route('/home', methods=['GET', 'POST'])
# def home():
#     try:
#         # Get the selected category from the request
#         selected_category = request.args.get('category', 'All')

#         # Get the search query from the request
#         search_query = request.args.get('search', '')

#         # Query posts based on the selected category
#         if selected_category == 'All':
#             posts = db.session.query(Post, User).join(User).all()
#         else:
#             posts = db.session.query(Post, User).join(User).filter(Post.category == selected_category).all()

#         # Filter posts containing the search term in the title
#         if search_query:
#             posts = [post for post in posts if search_query.lower() in post.Post.title.lower()]

#         # Create a list to store post data
#         post_list = []

#         # Iterate through the posts and append their data to the list
#         for post, user in posts:
#             post_data = {
#                 'id': post.id,
#                 'title': post.title,
#                 'category': post.category,
#                 'time': post.time.strftime('%Y-%m-%d %H:%M:%S'),  # Format timestamp as a string
#                 'image': post.image,
#                 'description': post.description,
#                 'user_id': post.user_id,
#                 'username': user.username,  # Include the username from the User model
#                 'profile_pic': user.profilepic,  # Include the profile picture from the User model
#             }

#             # Count the number of comments for each post
#             comment_count = Comment.query.filter(Comment.post_id == post_data['id']).count()
#             post_data['comment_count'] = comment_count

#             post_list.append(post_data)

#         # Reverse the order of post_list to display new posts at the beginning
#         post_list = post_list[::-1]

#         # Pass the post data, selected category, and search query to the 'home.html' template
#         return render_template('home.html', posts=post_list, selected_category=selected_category, search_query=search_query)
#     except SQLAlchemyError as e:
#         # Handle database-related errors
#         db.session.rollback()
#         error_message = 'An error occurred while retrieving data from the database: ' + str(e)
#         flash(error_message, 'error')
#         return render_template('home.html', posts=[], selected_category='All', search_query='')

#     except Exception as e:
#         # Handle other unexpected errors
#         error_message = 'An unexpected error occurred: ' + str(e)
#         flash(error_message, 'error')
#         return render_template('home.html', posts=[], selected_category='All', search_query='')


@app.route('/delete_post/<int:post_id>', methods=['GET'])
@login_required
def delete_post(post_id):
    post = Post.query.get(post_id)
    
    if post:
        # Check if the current user is either the post owner or an admin
        if current_user.admin or post.user_id == current_user.id:
            try:
                # If the user has permission, delete the post
                db.session.delete(post)
                db.session.commit()
                flash('Post deleted successfully.', 'success')
            except Exception as e:
                db.session.rollback()
                flash('Failed to delete the post. Error: ' + str(e), 'error')
        else:
            flash('Unauthorized to delete this post', 'error')
    else:
        flash('Post not found.', 'error')

    return redirect(url_for('home'))


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    try:
        logout_user()
        flash("You have been logged out.", "success")
    except Exception as e:
        flash("An error occurred while logging out: " + str(e), "error")
    
    return redirect(url_for('login'))  # Redirect to the login page


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # Log in the user using Flask-Login
            login_user(user)

            # Create an access token if you want to use JWT for authorization
            access_token = create_access_token(identity=user.id)

            # Redirect to the home page with the access token as a query parameter
            return redirect(url_for('home', access_token=access_token))

        # Handle invalid login credentials with flash messages
        flash('Invalid username or password', 'error')

    # Handle GET requests by rendering the login form
    return render_template('login.html')



def generate_avatar(email):
    email_hash = hashlib.md5(email.encode('utf-8')).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=identicon"
    return gravatar_url
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            # Generate a unique avatar for the user based on their username
            profilepic_url = generate_avatar(request.form['username'])  # Define this function
            name = request.form['name']
            email = request.form['email']
            username = request.form['username']
            password = request.form['password']

            # Check if the username or email already exists
            existing_user = User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first()

            if existing_user:
                flash('Username or email already exists', 'error')
                return redirect(url_for('signup'))

            # Create a new user
            new_user = User(
                username=username,
                email=email,
                name=name,
                profilepic=profilepic_url
            )

            # Hash the password using bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user.password = hashed_password

            # Assuming you have a database session, add the user and commit the session
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login'))  # Redirect to the signin page on successful signup

        except Exception as e:
            flash('An error occurred during the signup process. Please try again later.', 'error')
            app.logger.error(f'Signup error: {str(e)}')

    return render_template('signup.html')

# @app.route('/get_users', methods=['GET'])
# def get_users():
#     try:
#         users = User.query.all()
#         user_list = []

#         for user in users:
#             user_data = {
#                 'id': user.id,
#                 'username': user.username,
#                 'email': user.email,
#                 'name': user.name,
#                 'profilepic': user.profilepic
#                 # Add other fields you want to retrieve
#             }
#             user_list.append(user_data)

#         return render_template('user_list.html', users=user_list)
#     except Exception as e:
#         flash('An error occurred while fetching user data.', 'error')
#         app.logger.error(f'Error in get_users route: {str(e)}')

#     return render_template('error.html')  # Display an error page on failure

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        user_email = request.form['email']
        title = request.form['title']
        description = request.form['description']

        if not user_email or not title or not description:
            flash('Please fill in all fields.', 'error')
        else:
            # Send email with feedback
            msg = Message('Feedback', recipients=['feedback@example.com'])
            msg.html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
        }}
        .container {{
            max-width: 400px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }}
        h1 {{
            text-align: center;
            color: #333;
        }}
        .field-label {{
            font-weight: bold;
        }}
        .field-value {{
            color: #007bff;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Feedback Received</h1>
        <p class="field-label">From:</p>
        <p class="field-value">{user_email}</p>
        <p class="field-label">Title:</p>
        <p class="field-value">{title}</p>
        <p class="field-label">Description:</p>
        <p class="field-value">{description}</p>
    </div>
</body>
</html>
"""
            try:
                mail.send(msg)
                flash('Feedback submitted successfully. Thank you!', 'success')
            except Exception as e:
                flash('An error occurred while sending feedback. Please try again later.', 'error')
            
            return redirect(url_for('contact'))

    return render_template('contact.html')


@app.route('/forget', methods=['GET', 'POST'])
def forget():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a unique reset token
            reset_token = secrets.token_urlsafe(32)

            # Store the reset token in the database
            reset_token_entry = ResetToken(user_id=user.id, token=reset_token)
            db.session.add(reset_token_entry)
            db.session.commit()

            # Send the reset token to the user's email with HTML and CSS styling
            reset_link = f"http://localhost:5000/reset?token={reset_token}"  # Correct for local development

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
                flash('Password reset email sent. Please check your inbox.', 'success')
            except Exception as e:
                # Log the error
                traceback.print_exc()
                flash(f'Email not sent: {str(e)}', 'error')
        else:
            flash('Email not found. Please enter a valid email address.', 'error')

    return render_template('forget.html')


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'POST':
        token = request.form['token']
        new_password = request.form['password']
        
        reset_token_entry = ResetToken.query.filter_by(token=token).first()
        if not reset_token_entry:
            flash('Invalid reset token', 'error')
            return redirect(url_for('reset', token=token))  # Redirect back to the reset page with the token

        if not reset_token_entry.is_valid():
            flash('Reset token has expired', 'error')
            return redirect(url_for('reset', token=token))  # Redirect back to the reset page with the token

        user = User.query.get(reset_token_entry.user_id)

        # Update the user's password with the new password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password

        # Remove the used reset token from the database
        db.session.delete(reset_token_entry)
        db.session.commit()

        flash('Password reset successful. You can now log in with your new password.', 'success')
        return redirect(url_for('login'))

    # Render the "reset.html" template with the token
    return render_template('reset.html', token=request.args.get('token'))

@app.route('/post/edit/<int:post_id>', methods=['POST', 'PUT'])
@login_required
def edit_post(post_id):
    # Check if the post exists
    post = Post.query.get(post_id)

    if not post:
        flash('Post not found', 'error')
        return redirect(url_for('home'))  # Redirect to the home page

    # Check if the user is authorized to edit the post
    user_id = current_user.id

    if post.user_id != user_id and not current_user.admin:
        flash('Unauthorized to edit this post', 'error')
        return redirect(url_for('home'))  # Redirect to the home page

    if request.method in ['POST', 'PUT']:
        # Get the values from the form fields
        title = request.form.get('title', post.title)
        category = request.form.get('category', post.category)
        description = request.form.get('description', post.description)

        imgbb_image_url = post.image  # Initialize imgbb_image_url to the existing image URL

        if 'file' in request.files:
            image_file = request.files['file']
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)

                imgbb_image_url = upload_image_to_imgbb(image_path)

                if not imgbb_image_url:
                    flash('Image upload to ImgBB failed', 'error')
                    return redirect(url_for('home'))  # Redirect to the home page

        try:
            # Update the post's attributes
            post.title = title
            post.category = category
            post.description = description
            post.image = imgbb_image_url
            post.time = datetime.now()  # Update the time to the current time
            post.admin = current_user.admin  # Update the admin to the current user's admin status

            db.session.commit()

            flash('Post edited successfully', 'success')
            return redirect(url_for('view_post', post_id=post_id))
        except SQLAlchemyError as e:
            db.session.rollback()
            error_message = str(e)
            flash('Error while editing the post', 'error')
            print(f"Error while editing the post: {error_message}")
            return redirect(url_for('home'))  # Redirect to the home page

    return render_template('detail.html', post=post)


@app.route('/post/<int:post_id>', methods=['GET'])
def view_post(post_id):
    post = Post.query.get(post_id)
    user_id = None

    if current_user.is_authenticated:
        user_id = current_user.id

    if not post:
        return render_template('error.html', message='Post not found'), 404

    comments = Comment.query.filter(Comment.post_id == post_id).all()
    comment_data = []

    for comment in comments:
        user_name = comment.author.name if comment.author else None
        user_profilepic = comment.author.profilepic if comment.author else None

        comment_info = {
            'id': comment.id,
            'text': comment.text,
            'time': comment.time.strftime('%d/%m/%Y %H:%M:%S'),            'user_id': comment.user_id,
            'post_id': comment.post_id,
            'user_name': user_name,
            'user_profilepic': user_profilepic
        }

        comment_data.append(comment_info)

    # Determine the category of the currently viewed post
    post_category = post.category

    # Query related posts in the same category (excluding the currently viewed post)
    related_posts = Post.query.filter(Post.category == post_category, Post.id != post_id).limit(3).all()

    return render_template('detail.html', post=post, user_id=user_id, comments=comment_data, related_posts=related_posts)


@app.route('/create_comment/<int:post_id>', methods=['POST'])
@login_required
def create_comment(post_id):
    if request.method == 'POST':
        text = request.form.get('text')
        # Assuming you get user_id from the current_user
        user_id = current_user.id

        # Check if the post with the provided post_id exists
        post = Post.query.get(post_id)
        if not post:
            flash("Post not found", "error")
            return redirect(url_for('home'))  # Redirect to the home page

        if not text:
            flash("Comment text is required", "error")
            return redirect(url_for('view_post', post_id=post_id))  # Redirect back to the post page

        new_comment = Comment(
            text=text,
            user_id=user_id,
            post_id=post_id,
            time=datetime.utcnow()
        )

        db.session.add(new_comment)

        try:
            db.session.commit()
            flash("Comment added successfully", "success")
        except Exception as e:
            db.session.rollback()
            flash("Failed to add the comment. Error: " + str(e), "error")

        return redirect(url_for('view_post', post_id=post_id))

    # Handle other HTTP methods, if needed
    return "Method not allowed", 405


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    # Retrieve the comment with the given comment_id
    comment = Comment.query.get(comment_id)

    if comment:
        post_id = comment.post.id  # Access the post id from the comment

        # Check if the current user is either the comment author or the post author
        if comment.user_id == current_user.id or comment.post.author.id == current_user.id:
            # If the user has permission, delete the comment
            db.session.delete(comment)
            db.session.commit()
            flash('Comment deleted successfully.', 'success')
        else:
            flash('You do not have permission to delete this comment.', 'error')
    else:
        flash('Comment not found or an error occurred.', 'error')  # Updated error message

    # Redirect back to the post with the specified post_id
    return redirect(url_for('view_post', post_id=post_id))

# Define an error handler for HTTP error code 404 (Page Not Found)
@app.errorhandler(404)
def page_not_found(error):
    # Render the 'notfound.html' template and return a 404 error code
    return render_template('notfound.html'), 404

# Define a route that intentionally raises a 404 error
@app.route('/nonexistent-page')
def nonexistent_page():
    # Manually raise a 404 error using the "abort" function
    abort(404)


@login_manager.user_loader
def load_user(user_id):
    # Load the user by user ID
    return User.query.get(int(user_id))


@app.after_request
def add_header(response):
    """
    Add caching control headers to responses.

    This function sets the 'max-age' directive in the 'Cache-Control' header of responses,
    which specifies the maximum amount of time a response can be cached by a client.

    Adjust the value (300 seconds in this example) as needed based on your caching requirements.
    """
    response.cache_control.max_age = 300  # Adjust this value as needed
    return response

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
