from flask import Flask, request, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, FileField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt  # Import Flask-Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)  # Initialize Flask-Bcrypt

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    public_id = db.Column(db.String(120))
    admin = db.Column(db.Boolean, default=False)
    uemail = db.Column(db.String(120))
    profilepic = db.Column(db.String(120))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    name = StringField('Name', validators=[DataRequired()])
    public_id = StringField('Public ID')
    admin = BooleanField('Admin', default=False)
    uemail = StringField('UEmail')
    profilepic = FileField('Profile Picture')

@app.route('/register', methods=['POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        name = form.name.data
        public_id = form.public_id.data
        admin = form.admin.data
        uemail = form.uemail.data
        profilepic = form.profilepic.data

        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'error': 'Username already exists'}), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create and save the user in the database
        user = User(
            username=username,
            email=email,
            password=hashed_password,
            name=name,
            public_id=public_id,
            admin=admin,
            uemail=uemail,
            profilepic=profilepic
        )
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 201

    return jsonify({'error': 'Invalid data'}), 400

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
