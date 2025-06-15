import re

from flask_wtf import FlaskForm
from wtforms import Form, StringField, EmailField, PasswordField, SelectField, FloatField, SubmitField, validators, DateField, StringField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, Email, Regexp, ValidationError, EqualTo, NumberRange
from flask_wtf.file import FileField, FileAllowed
from datetime import datetime
from datetime import date
import decimal


class CreateUserForm(FlaskForm):
    first_name = StringField('First Name', [Length(min=1, max=150), DataRequired()])
    last_name = StringField('Last Name', [Length(min=1, max=150), DataRequired()])
    email = EmailField('Email', [Email(), DataRequired()])
    password = PasswordField('Password', [
        Length(min=8, max=50, message="Password must be between 8 and 50 characters."),
        DataRequired(),
        validators.Regexp(
            regex="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$",
            message="Password must have at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character."
        )
    ])
    confirm_password = PasswordField('Confirm Password', [
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    contact_number = StringField(
        'Contact Number',
        [Length(min=8, max=8), DataRequired(message="Contact number is required.")]
    )
    address = StringField('Address', [
        Length(min=15, max=200, message="Address must be at least 15 characters long."),
        DataRequired()
    ])

    def validate_contact_number(self, field):
        if not field.data.isdigit():
            raise ValidationError("Contact number must contain only numeric digits (0-9).")


class AddToyForm(FlaskForm):
    name = StringField('Toy Name', [validators.DataRequired(), validators.length(min=2, max=100)])
    description = StringField('Description', [validators.DataRequired(), validators.length(min=10)])

    # Store as StringField to keep input as a string
    price = StringField('Price', [
        validators.DataRequired(message="Price is required."),
    ])

    category = SelectField(
        'Category',
        choices=[
            ('dolls', 'Dolls'),
            ('lego', 'Lego'),
            ('stuffed_toys', 'Stuffed Toys'),
            ('board_games', 'Board Games')
        ],
        validators=[validators.DataRequired(message="Please select a category.")]
    )

    image = FileField('Upload Image', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])

    def validate_price(self, field):
        """ Ensure price is a valid float with 2 decimal places """
        try:
            price_value = decimal.Decimal(field.data)
            if price_value < 20.01:
                raise ValidationError("Price must be greater than 20.")
        except decimal.InvalidOperation:
            raise ValidationError("Price must be a valid numerical value.")




class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', [
        validators.DataRequired(message="New password is required."),
        validators.Length(min=8, max=50, message="Password must be between 8 and 50 characters."),
        validators.Regexp(
            regex="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$",
            message="Password must have at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character."
        )
    ])

    confirm_password = PasswordField('Confirm Password', [
        validators.DataRequired(message="Please confirm your password."),
        validators.EqualTo('new_password', message="Passwords must match.")
    ])


class PaymentForm(FlaskForm):
    name = StringField('Full Name', [DataRequired(), Length(max=100)])
    email = EmailField('Email', [DataRequired(), Email()])
    address = StringField('Address', [DataRequired(), Length(max=200)])
    card_number = StringField('Card Number', [DataRequired(), Regexp(r'^\d{16}$', message="Card number must be 16 digits")])
    expiration_date = StringField('Expiration Date (MM/YY)', [DataRequired(), Regexp(r'^\d{2}/\d{2}$', message="Use format MM/YY")])
    cvv = StringField('CVV', [DataRequired(), Regexp(r'^\d{3}$', message="CVV must be 3 digits")])
    submit = SubmitField('Submit Payment')


class CreateDiscountForm(Form):
    name = StringField('Discount Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    percentage = FloatField('Percentage', [validators.NumberRange(min=0, max=100), validators.InputRequired()])
    startdate = DateField('Start Date', format='%Y-%m-%d')
    enddate = DateField('End Date', format='%Y-%m-%d')

    def validate_startdate(self, field):
        today = datetime.now().date()
        if field.data < today:
            raise validators.ValidationError('Start date cannot be set in the past.')

    def validate_enddate(self, field):
        today = datetime.now().date()
        if field.data < today:
            raise validators.ValidationError('End date cannot be set in the past.')
        if self.startdate.data and field.data < self.startdate.data:
            raise validators.ValidationError('End date cannot be set before the start date.')


class CreateReviewForm:
    def __init__(self):
        # Assign each field as an instance variable
        self.user_id = StringField('User ID', validators=[DataRequired()])
        self.rating = IntegerField('Rating', validators=[DataRequired(), NumberRange(min=1, max=5)], render_kw={"placeholder": "Enter Rating (1 to 5)"})
        self.comment = TextAreaField('Review Comment', validators=[DataRequired(), Length(min=10, message="Feedback must be at least 10 characters long.")])
        self.date = DateField('Review Date', format='%Y-%m-%d', default=date.today, validators=[DataRequired()])
        self.image = FileField('Upload Image')  # Add file upload field

class CreateFeedbackForm:
    def __init__(self):
        self.user_id = IntegerField('Customer ID', [DataRequired(), NumberRange(min=1, message="Customer ID must be a positive integer")])
        self.first_name = StringField('First Name', [Length(min=1, max=150), DataRequired()])
        self.last_name = StringField('Last Name', [Length(min=1, max=150), DataRequired()])
        self.email = EmailField('Email', [Email(), DataRequired()])
        self.satisfactory = IntegerField('Satisfaction Rating', [DataRequired(), NumberRange(min=1, max=5, message="Rating must be between 1 and 5")])
        self.improvements = TextAreaField('Improvements Suggested', [Length(max=500), Length(min=20, message="Feedback must be at least 20 characters long.")])
        self.date_posted = DateField('Date Submitted', format='%Y-%m-%d', default=date.today, validators=[DataRequired()])  # ✅ Auto-fill today's date


class CreateQnAForm:
    def __init__(self):
        self.question = TextAreaField('Your Question', [DataRequired(message="Please enter your question."), Length(min=5, max=500, message="Question must be between 5 and 500 characters.")])
        self.user_id = StringField('User ID', validators=[DataRequired()])
        self.rating = IntegerField('Rating', validators=[DataRequired(), NumberRange(min=1, max=5)], render_kw={"placeholder": "Enter Rating (1 to 5)"})
        self.date_published = DateField('Review Date', format='%Y-%m-%d', default=date.today, validators=[DataRequired()])

def check_if_alpha(form, field):
    if not field.data.isalpha():
        raise ValidationError('Text must be string and have no spaces')
    else :
        return

# Custom validator to check for valid monetary format
def is_money_format(form, field):
    value = field.data
    # Ensure the value is a positive integer or float, but allows decimal point (for cents)
    if value is not None:
        if not re.match(r'^\d+(\.\d{1,2})?$', str(value)):  # Only allows numbers with up to 2 decimal places
            raise validators.ValidationError('Please enter a valid money format (e.g., 25.50)')


class CreateTradeToyForm(Form):
    # Name of the toy can take any text without length restrictions
    name = StringField('Name of Toy', [validators.DataRequired()])

    # Price field with a custom validator for money format
    price = StringField('Value of Toy', [
        validators.DataRequired(),
        is_money_format,  # Ensure the price is a valid money format (e.g., 25.50)
    ])

    # Remarks field with optional description (max 50 characters)
    remarks = TextAreaField('Description - Optional', [
        validators.Optional(),
        validators.Length(min=1, max=50, message='Must be within 50 characters')
    ])
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!'),])




