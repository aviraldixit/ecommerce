from flask_wtf import FlaskForm
from wtforms import validators, StringField, PasswordField, BooleanField, TextAreaField, IntegerField, HiddenField
from wtforms.validators import InputRequired, Length
from wtforms.fields.html5 import EmailField, TelField
from flask_wtf.file import FileField, FileAllowed
from flask_uploads import IMAGES


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired('A full name is required.'), Length(max=100,
                                                                                             message='Your name can\'t be more than 100 characters.')])
    email = EmailField('Email address', [validators.DataRequired(), validators.Email()])

    password = StringField(label='Password', validators=[
        validators.Length(min=6, max=20),
        validators.EqualTo('password_confirm', message='Passwords must match')
    ])
    password_confirm = StringField(label='Confirm Password', validators=[
        validators.Length(min=6, max=20)
    ])


class ContactForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired('A full name is required.'), Length(max=100,
                                                                                             message='Your name can\'t be more than 100 characters.')])
    email = EmailField('Email address', [validators.DataRequired(), validators.Email()])

    message = TextAreaField('Message', validators=[InputRequired('Message is required.')])


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired('Email is required.'),
                                             Length(max=30, message='Your email is too many characters.')])
    password = PasswordField('Password', validators=[InputRequired('A password is required.')])
    remember = BooleanField('Remember me')


class AddProduct(FlaskForm):
    name = StringField('Name')
    price = IntegerField('Price')
    category = StringField('Product Category')
    stock = IntegerField('Stock')
    description = TextAreaField('Description')
    image = FileField('Image', validators=[FileAllowed(IMAGES, 'Only images are accepted.')])


class AddToCart(FlaskForm):
    quantity = IntegerField('Quantity')
    id = HiddenField('ID')


class Checkout(FlaskForm):
    first_name = StringField('First Name')
    last_name = StringField('Last Name')
    phone_number = TelField('Phone Number')
    email = StringField('Email')
    address = StringField('Address')
    city = StringField('City')
    state = StringField('State')
    country = StringField('Country')
    postal_code = StringField('Postal Code')
    default_address = BooleanField('Default Address')


class UpdateProfileForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired('A full name is required.'), Length(max=100,
                                                                                             message='Your name can\'t be more than 100 characters.')])
    email = EmailField('Email address', [validators.DataRequired(), validators.Email()])

    password = StringField(label='Password', validators=[
        validators.DataRequired()])
