from flask import Flask, request, jsonify,session,flash,make_response,send_from_directory,send_file
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
from flask_jwt_extended import JWTManager,create_access_token,jwt_required,get_jwt_identity
from flask import redirect, url_for, render_template, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url
import requests



app = Flask(__name__, static_folder='static')

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
app.config['JWT_SECRET_KEY'] = '72d630c0cef6c01bff062d80'  # Replace with a strong secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Set token expiration time



jwt = JWTManager(app)
db=SQLAlchemy(app)
bcrypt = Bcrypt(app) 
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = "login" 



class User(UserMixin,db.Model):
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

def load_user(user_id):
    return User.query.get(int(user_id))


# Define your Imgur client ID and secret
IMGUR_CLIENT_ID = 'f4b1b04c693195a'
IMGUR_CLIENT_SECRET = '81d18bcbe5d1ab6068bbd993b193f2946e9ccbab'

imgur_client = ImgurClient(IMGUR_CLIENT_ID, IMGUR_CLIENT_SECRET)





# @app.route('/post/edit/<int:post_id>', methods=['PUT'])
# @jwt_required()
# def edit_post(post_id):
#     # Check if the post exists
#     post = Post.query.get(post_id)

#     if not post:
#         return jsonify({'message': 'Post not found'}), 404

#     # Check if the user is authorized to edit the post
#     user_email = request.form.get('email')  # You might need to adapt this based on your request format
#     user = User.query.filter_by(email=user_email).first()

#     if not user:
#         return jsonify({'message': 'User not found'}), 404

#     # Check if the user is the author of the post or has admin privileges
#     if post.user_id != user.id and not user.admin:
#         return jsonify({'message': 'Unauthorized to edit this post'}), 403

#     # Check if an image file is provided in the request
#     imgur_link = post.image
#     if 'file' in request.files:
#         image_file = request.files['file']
#         if image_file and allowed_file(image_file.filename):
#             filename = secure_filename(image_file.filename)
#             image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             image_file.save(image_path)
#             imgur_response = upload_image_to_imgur(image_path)

#             if imgur_response:
#                 imgur_link = imgur_response['link']
#             else:
#                 return jsonify({'message': 'Image upload to Imgur failed'}), 500
#         else:
#             return jsonify({'message': 'File upload failed. Allowed file extensions: png, jpg, jpeg, gif'}), 400

#     # Update the post's attributes
#     post.title = request.form.get('title', post.title)
#     post.category = request.form.get('category', post.category)
#     post.description = request.form.get('description', post.description)
#     post.image = imgur_link

#     db.session.commit()

#     return jsonify({'message': 'Post edited successfully'}), 200





@app.route('/posts', methods=['GET'])
def get_all_posts():
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

    return jsonify(post_list)



@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        description = request.form['description']
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
        db.session.commit()

        access_token = create_access_token(identity=current_user.id)

        response = make_response(jsonify({'message': 'Post created successfully'}), 201)  # Use make_response
        response.headers['Authorization'] = f'Bearer {access_token}'

        return redirect(url_for('home'))

    return render_template('post.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

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





@app.route('/post/edit/<int:post_id>', methods=['POST', 'PUT'])
@login_required
def edit_post(post_id):
    # Check if the post exists
    post = Post.query.get(post_id)

    if not post:
        return jsonify({'message': 'Post not found'}), 404

    # Check if the user is authorized to edit the post
    user_id = current_user.id

    if post.user_id != user_id and not current_user.admin:
        return jsonify({'message': 'Unauthorized to edit this post'}), 403

    if request.method == 'POST':
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
                    return jsonify({'message': 'Image upload to ImgBB failed'}), 500

        # Update the post's attributes
        post.title = title
        post.category = category
        post.description = description
        post.image = imgbb_image_url
        post.time = datetime.now()  # Update the time to the current time
        post.admin = current_user.admin  # Update the admin to the current user's admin status

        db.session.commit()

        access_token = create_access_token(identity=current_user.id)

        response = make_response(jsonify({'message': 'Post edited successfully'}), 200)
        response.headers['Authorization'] = f'Bearer {access_token}'

        javascript_code = """
        <script>
            setTimeout(function() {
                location.reload();
            }, 1000);  // Refresh after 1 second (adjust as needed)
        </script>
        """

    return render_template('detail.html', post=post)





@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    # Query all posts and related user information from the database
    posts = db.session.query(Post, User).join(User).all()

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
        post_list.append(post_data)

    # Pass the post data to the 'home.html' template
    return render_template('home.html', posts=post_list)
# ///////////endpost/////////////

@app.route('/post/<int:post_id>', methods=['GET'])
def view_post(post_id):
    post = Post.query.get(post_id)

    if post:
        post = {
            'id': post.id,
            'title': post.title,
            'category': post.category,
            'time': post.time.strftime("%d/%m/%Y"),
            'image': post.image,
            'description': post.description,
            'user_id': post.user_id,
        }
        return render_template('detail.html',post=post)
    else:
        return jsonify({'error': 'Post not found'}), 404


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



@app.route('/contact', methods=['GET','POST'])
def contact():
    return render_template('contact.html')


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))  # Redirect to the login page



# Assuming you have already configured and initialized Flask-Login and Flask-JWT-Extended

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

        return jsonify({'message': 'Invalid username or password'}), 400  # Return an error message

    # Handle GET requests by rendering the login form
    return render_template('login.html')

# Use the @login_required decorator to protect routes that require authentication


# Define a function to generate avatars based on user data
def generate_avatar(username):
    # Customize the avatar using the user's username or other unique data
    avatar_url = f"https://ui-avatars.com/api/?name={username}&background=random"
    return avatar_url

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Generate a unique avatar for the user based on their username
        profilepic_url = generate_avatar(request.form['username'])  # Define this function
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Check if the username or email already exists
        existing_user = User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first()

        if existing_user:
            return jsonify({'message': 'Username or email already exists'}), 400

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

    return render_template('signup.html')




# //////////endregister///////////////


# /////////////reset_password//////////




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
            reset_link = f"http://localhost:5000/reset?token={reset_token}"  # Update URL accordingly

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

        # Redirect the user to the login page after a successful password reset
        return redirect(url_for('login'))

    # Render the "reset.html" template with the token
    return render_template('reset.html', token=request.args.get('token'))



# /////////////end reset_password//////////



# //////////comment////////////////



@app.route('/comment', methods=['POST'])
@jwt_required()
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
@jwt_required()
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
@jwt_required()
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


@login_manager.user_loader
def load_user(user_id):
    # Load the user by user ID
    return User.query.get(int(user_id))


# //////////////endcomment///////////
@app.after_request
def add_header(response):
    response.cache_control.max_age = 300  # Adjust this value as needed
    return response

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
