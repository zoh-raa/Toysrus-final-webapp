
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response , jsonify
from Forms import CreateUserForm, AddToyForm , PaymentForm, ResetPasswordForm, CreateDiscountForm, CreateFeedbackForm, CreateReviewForm, CreateQnAForm
import shelve, User, pprint, re
from Toy import Toy
from datetime import datetime
from authlib.integrations.flask_client import OAuth
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
import random
import pickle
import dbm
import uuid
from Review import Review
import Feedback
from datetime import date
from werkzeug.utils import secure_filename
import csv
from io import StringIO
from Feedback import Feedback
from qna import qna
import requests
from transformers import pipeline
from collections import Counter
from Discount import Discount
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for session management
app.config['WTF_CSRF_ENABLED'] = False


app.config['WTF_CSRF_ENABLED'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure Flask-Mail for sending emails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False  # ✅ Make sure this is False
app.config['MAIL_USERNAME'] = 'toysruswebapp@gmail.com'  # Replace with your Gmail
app.config['MAIL_PASSWORD'] = 'enbf lsit dsqt wcuq'  # Use an App Password


HEADERS = {"Authorization": "Bearer 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"}  # Replace with your token


mail = Mail(app)

@app.before_request
def clear_session_on_startup():
    if not session.get('initialized'):  # Ensures session is cleared only once per app restart
        session.clear()
        session['user_role'] = 'guest'
        session['initialized'] = True

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Google OAuth Setup
app.config['GOOGLE_CLIENT_ID'] = "708969207849-d1hq3ccoaf2qsu3ci0asva5kfr4j65d1.apps.googleusercontent.com"
app.config['GOOGLE_CLIENT_SECRET'] = "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"
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={"scope": "openid email profile"},
)


def initialize_staff_db():
    with shelve.open('staff.db', 'c') as db:
        staff_dict = {
            1: {"email": "bobby24@mytoysrus.com", "password": "admin123"},
            2: {"email": "daeho388@mytoysrus.com", "password": "password123"},
        }
        db['Staff'] = staff_dict


@app.route('/')
def home():
    return render_template('home.html')

def initialize_user_id():
    try:
        with shelve.open('user.db', 'c') as db:
            users_dict = db.get('Users', {})
            if users_dict:
                User.count_id = max(users_dict.keys())  # Get the highest user ID
            else:
                User.count_id = 0
    except Exception as e:
        print(f"Error initializing user ID: {e}")


@app.route('/createUser', methods=['GET', 'POST'])
def create_user():
    session.pop('from_login', None)
    session.clear()  # Ensure no lingering session data

    create_user_form = CreateUserForm(request.form)

    if request.method == 'POST':
        print(f"Form data submitted: {request.form}")  # Debugging

        # ✅ Check form validation
        if create_user_form.validate():
            print("Form validation successful.")  # Debugging
            session.clear()  # Ensure no lingering session data
            db = shelve.open('user.db', 'c')
            try:
                users_dict = db.get('Users', {})
                User.User.count_id = len(users_dict)

                user = User.User(
                    create_user_form.first_name.data,
                    create_user_form.last_name.data,
                    create_user_form.email.data,
                    create_user_form.password.data,
                    create_user_form.contact_number.data,
                    create_user_form.address.data,
                )

                users_dict[user.get_user_id()] = user
                db['Users'] = users_dict
                db.close()

                flash("Account successfully created! Please log in.", "success")
                return redirect(url_for('login'))

            except Exception as e:
                print(f"Error writing to database: {e}")  # Debugging
                flash("Database error. Please try again.", "danger")

        else:
            print(f"Form validation errors: {create_user_form.errors}")  # Debugging
            for field, errors in create_user_form.errors.items():
                for error in errors:
                    flash(f"{create_user_form[field].label.text}: {error}", "danger")

    return render_template('createUser.html', form=create_user_form)

@app.route('/retrieveUsers')
def retrieve_users():
    users_dict = {}
    db = shelve.open('user.db', 'c')
    users_dict = db['Users']
    db.close()

    users_list = []
    for key in users_dict:
        user = users_dict.get(key)
        users_list.append(user)

    return render_template('retrieveUsers.html', count=len(users_list), users_list=users_list)


@app.route('/updateUser/<int:id>/', methods=['GET', 'POST'])
def update_user(id):
    update_user_form = CreateUserForm(request.form)

    if request.method == 'POST':
        with shelve.open('user.db', 'w') as db:
            users_dict = db.get('Users', {})
            user = users_dict.get(id)

            if user:
                if update_user_form.first_name.data:
                    user.set_first_name(update_user_form.first_name.data)
                if update_user_form.last_name.data:
                    user.set_last_name(update_user_form.last_name.data)
                if update_user_form.email.data:
                    user.set_email(update_user_form.email.data)
                if update_user_form.contact_number.data:
                    user.set_contact_number(update_user_form.contact_number.data)
                if update_user_form.address.data:
                    user.set_address(update_user_form.address.data)

                db['Users'] = users_dict
                flash("Your account has been updated!", "success")

        return redirect(url_for('account'))

    else:
        with shelve.open('user.db', 'c') as db:
            users_dict = db.get('Users', {})
            user = users_dict.get(id)

            if user:
                update_user_form.first_name.data = user.get_first_name()
                update_user_form.last_name.data = user.get_last_name()
                update_user_form.email.data = user.get_email()
                update_user_form.contact_number.data = user.get_contact_number()
                update_user_form.address.data = user.get_address()

    return render_template('updateUser.html', form=update_user_form)


@app.route('/deleteUser/<int:id>', methods=['POST'])
def delete_user(id):
    with shelve.open('user.db', 'w') as db:
        users_dict = db.get('Users', {})
        if id in users_dict:
            del users_dict[id]
            db['Users'] = users_dict
            flash("Your account has been deleted.", "success")
        else:
            flash("User not found.", "danger")
    return redirect(url_for('home'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user_found = False  # Track if the user exists in any database

        # Staff account logic
        if email.endswith('@mytoysrus.com'):
            with shelve.open('staff.db', 'c') as db:
                staff_dict = db.get('Staff', {})
                staff = next((s for s in staff_dict.values() if s['email'] == email), None)
                if staff and staff['password'] == password:
                    session['logged_in'] = True
                    session['user_role'] = 'staff'
                    session['user_email'] = email
                    flash("Welcome, Staff Member!", "success")
                    return redirect(url_for('staff_dashboard'))  # Redirect staff to dashboard
                user_found = True  # Email exists, but password incorrect

        else:
            # Customer account logic
            with shelve.open('user.db', 'c') as db:
                users_dict = db.get('Users', {})
                user = next((u for u in users_dict.values() if u.get_email() == email), None)
                if user and user.get_password() == password:
                    session['logged_in'] = True
                    session['user_role'] = 'customer'
                    session['user_email'] = email
                    session['user_id'] = user.get_user_id()
                    flash("Login successful!", "success")
                    return redirect(url_for('account'))
                if user:
                    user_found = True  # Email exists, but password incorrect

        flash("Incorrect login credentials. Try to login again", "danger")
    return render_template('login.html')


otp_store = {}  # Temporary storage for OTPs

@app.route('/password_request', methods=['GET', 'POST'])
def password_request():
    if request.method == 'POST':
        email_or_phone = request.form.get('email_or_phone')

        # Check if user exists
        with shelve.open('user.db', 'c') as db:
            users_dict = db.get('Users', {})
            user = next((u for u in users_dict.values() if u.get_email() == email_or_phone or u.get_contact_number() == email_or_phone), None)

        if not user:
            flash("User not found!", "danger")
            return redirect(url_for('password_request'))

        # Generate OTP
        otp = str(random.randint(100000, 999999))
        otp_store[email_or_phone] = otp  # Store OTP temporarily

        # Send OTP via email
        msg = Message('Password Change OTP', sender='toysruswebapp@gmail.com', recipients=[email_or_phone])
        msg.body = f'Your OTP for password change is: {otp}. This OTP expires in 10 minutes.'
        mail.send(msg)

        flash("OTP sent to your email/phone!", "success")
        return redirect(url_for('verify_otp', email_or_phone=email_or_phone))

    return render_template('password_request.html')


@app.route('/verify_otp/<email_or_phone>', methods=['GET', 'POST'])
def verify_otp(email_or_phone):
    if request.method == 'POST':
        user_otp = request.form.get('otp')

        # Check if OTP matches
        if otp_store.get(email_or_phone) == user_otp:
            flash("OTP Verified! You can now reset your password.", "success")
            return redirect(url_for('reset_password', email_or_phone=email_or_phone))
        else:
            flash("Invalid OTP! Please try again.", "danger")

    return render_template('verify_otp.html', email_or_phone=email_or_phone)


@app.route('/reset_password/<email_or_phone>', methods=['GET', 'POST'])
def reset_password(email_or_phone):
    form = ResetPasswordForm()

    if form.validate_on_submit():
        new_password = form.new_password.data

        # Update password in the database
        with shelve.open('user.db', 'w') as db:
            users_dict = db.get('Users', {})
            user = next((u for u in users_dict.values() if u.get_email() == email_or_phone or u.get_contact_number() == email_or_phone), None)

            if user:
                user.set_password(new_password)
                db['Users'] = users_dict
                flash("Password updated successfully! Please log in.", "success")
                return redirect(url_for('login'))

        flash("Error updating password!", "danger")

    return render_template('reset_password.html', form=form)




@app.route('/login/google')
def login_google():
    return google.authorize_redirect(url_for('google_callback', _external=True))

@app.route('/login/callback')
def google_callback():
    from User import User  # ✅ Ensure we import User correctly

    token = google.authorize_access_token()
    user_info = oauth.google.get("https://openidconnect.googleapis.com/v1/userinfo").json()

    if 'email' not in user_info:
        flash("Google authentication failed.", "danger")
        return redirect(url_for('login'))

    email = user_info['email']
    name = user_info.get('name', email.split('@')[0])  # Use email prefix if name isn’t available

    # Store Google user in session
    session['logged_in'] = True
    session['user_role'] = 'customer'
    session['user_email'] = email
    session['user_name'] = name

    with shelve.open('user.db', 'c') as db:
        users_dict = db.get('Users', {})

        # ✅ Fix reference to User.count_id
        User.count_id = len(users_dict)

        # ✅ Check if the user already exists in the database
        existing_user = next((u for u in users_dict.values() if hasattr(u, "get_email") and u.get_email() == email), None)

        if not existing_user:
            # ✅ Correctly create a Google user
            new_user = User(
                name,  # First Name
                "",  # Last Name (Google users may not have this)
                email,
                "",  # No password for Google users
                "",  # No contact number
                ""  # No address
            )

            users_dict[new_user.get_user_id()] = new_user
            db['Users'] = users_dict

            # Save user ID in session
            session['user_id'] = new_user.get_user_id()
        else:
            session['user_id'] = existing_user.get_user_id()

    flash("Google Login Successful!", "success")
    return redirect(url_for('account'))



from functools import wraps

def staff_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in') or session.get('user_role') != 'staff':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/account')
def account():
    if not session.get('logged_in'):
        flash("Please log in to access your account.", "warning")
        return redirect(url_for('login'))

    user = None

    # ✅ If user is from the database
    if session.get('user_role') == 'customer' and session.get('user_id'):
        with shelve.open('user.db', 'c') as db:
            users_dict = db.get('Users', {})
            user = users_dict.get(session.get('user_id'))

    # ✅ If user is logged in via Google, simulate a user object
    elif session.get('user_email'):
        user = {
            "get_first_name": lambda: session.get("user_name"),  # Simulate method
            "get_email": lambda: session.get("user_email"),
            "get_last_name": lambda: "N/A",
            "get_contact_number": lambda: "N/A",
            "get_address": lambda: "N/A",
            "get_user_id": lambda: "GoogleUser"
        }

    return render_template('account_page.html', user=user)

@app.route('/staff_dashboard')
@staff_required
def staff_dashboard():
    # Mock recent toy updates
    recent_toys = [
        {"name": "Super Action Figure", "category": "Action Toys", "updated_at": "2024-02-10"},
        {"name": "Dollhouse Set", "category": "Dolls", "updated_at": "2024-02-08"},
        {"name": "Lego Spaceship", "category": "Lego", "updated_at": "2024-02-07"},
        {"name": "Teddy Bear", "category": "Stuffed Toys", "updated_at": "2024-02-06"},
        {"name": "Board Game: Strategy King", "category": "Board Games", "updated_at": "2024-02-05"},
    ]

    # Mock customer inquiries
    recent_inquiries = [
        {"customer_email": "jane.doe@example.com", "message": "Do you have more Lego sets?"},
        {"customer_email": "john.smith@example.com", "message": "Can I return a defective toy?"},
        {"customer_email": "mary.jones@example.com", "message": "What’s the best board game for 10-year-olds?"},
    ]

    # Mock sales data
    sales_data = {
        "monthly": 15000,
        "top_seller": "Lego Classic Set",
        "total_orders": 320,
        "customer_satisfaction": "92% Positive Feedback",
    }

    return render_template(
        'staff_dashboard.html',
        recent_toys=recent_toys,
        recent_inquiries=recent_inquiries,
        sales_data=sales_data
    )



@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/debug_users')
def debug_users():
    db = shelve.open('user.db', 'c')
    try:
        users_dict = db.get('Users', {})
        debug_info = []
        for user_id, user in users_dict.items():
            debug_info.append({
                'user_id': user_id,
                'first_name': user.get_first_name(),
                'last_name': user.get_last_name(),
                'email': user.get_email(),
                'password': user.get_password(),
                'contact_number': user.get_contact_number(),
                'address': user.get_address(),
            })
        return {"users": debug_info}
    finally:
        db.close()


@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("query", "").strip().lower()
    if query:
        with shelve.open('searches.db', 'c', writeback=True) as db:
            if "Searches" not in db:  # ✅ Ensure key exists
                db["Searches"] = []

            searches = db["Searches"]  # Get searches safely

            searches.append({
                "user": session.get('user_email', 'Guest'),
                "query": query,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "deleted": False  # Track deletions
            })
            db["Searches"] = searches  # Save back safely

    return render_template("search_results.html", query=query)




@app.context_processor
def inject_recent_searches():
    user_email = session.get('user_email', 'Guest')

    searches = []  # Default to an empty list

    try:
        with shelve.open('searches.db', 'c') as db:  # ✅ 'c' mode creates file if missing
            searches = db.get('Searches', [])
    except (KeyError, EOFError, pickle.UnpicklingError, dbm.error) as e:
        print(f"Error accessing searches.db: {e}")

        # Delete corrupted files and reset database
        for ext in [".db", ".db.bak", ".db.dat", ".db.dir"]:
            db_path = f"searches{ext}"
            if os.path.exists(db_path):
                os.remove(db_path)

        searches = []  # Reset to empty list

    # Only return searches for the logged-in user
    user_searches = [search for search in searches if search["user"] == user_email]

    return dict(searches=user_searches)


@app.route("/recent_searches")
def recent_searches():
    if session.get('user_role') != 'staff':
        flash("Access restricted to staff only.", "danger")
        return redirect(url_for('login'))

    searches = []

    try:
        with shelve.open('searches.db', 'c') as db:  # 'c' prevents crashes from missing files
            searches = db.get('Searches', [])
    except (KeyError, EOFError, pickle.UnpicklingError, dbm.error) as e:
        print(f"Error accessing searches.db: {e}")

        # Delete corrupted files and reset database
        for ext in [".db", ".db.bak", ".db.dat", ".db.dir"]:
            db_path = f"searches{ext}"
            if os.path.exists(db_path):
                os.remove(db_path)

        searches = []  # Reset to empty list

    return render_template("recent_searches.html", all_searches=searches)


@app.route("/delete_search", methods=["POST"])
def delete_search():
    query = request.form.get("query")
    user_email = session.get('user_email', 'Guest')

    with shelve.open('searches.db', 'c', writeback=True) as db:
        searches = db.get('Searches', [])

        # Mark search as deleted for this user instead of removing it
        for search in searches:
            if search["query"] == query and search["user"] == user_email:
                search["deleted"] = True  # New flag to mark as deleted

        db["Searches"] = searches  # Save the updated data

        print(f"Marked search as deleted for {user_email}: {query}")  # Debugging

    return "", 204  # No content response


def initialize_toy_db():
    with shelve.open('toys.db', 'c') as db:
        if 'Toys' not in db:
            db['Toys'] = {}
            print("Initialized toy database.")

@app.route('/catalog')
def catalog():
    with shelve.open('toys.db', 'c') as db:
        toys_dict = db.get('Toys', {})
        toys_list = list(toys_dict.values())  # Convert dictionary values to a list
        print(f"Debug: Catalog toys - {[toy.get_name() for toy in toys_list]}")  # Debugging
    return render_template('catalog.html', toys=toys_list)


@app.route('/toys/add', methods=['GET', 'POST'])
@staff_required
def add_toy():
    form = AddToyForm()

    if form.validate_on_submit():
        file = request.files['image']
        if file and '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            with shelve.open('toys.db', 'c') as db:
                toys_dict = db.get('Toys', {})
                Toy.count_id = len(toys_dict)

                toy = Toy(
                    form.name.data,
                    form.description.data,
                    form.price.data,
                    form.category.data,
                    filename,  # ✅ Store only the filename
                    quantity=1  # ✅ Start with a default quantity of 1
                )

                toys_dict[toy.get_toy_id()] = toy
                db['Toys'] = toys_dict

            flash(f"Toy '{toy.get_name()}' added successfully!", "success")
            return redirect(url_for('catalog'))

    return render_template('createToy.html', form=form)



@app.route('/toys/retrieve')
@staff_required
def retrieve_toys():
    with shelve.open('toys.db', 'w') as db:  # ✅ Open in write mode to update old toys
        toys_dict = db.get('Toys', {})

        for toy_id, toy in toys_dict.items():
            if not hasattr(toy, '_Toy__quantity'):  # ✅ Add quantity to old toys
                toy.set_quantity(1)
                toys_dict[toy_id] = toy  # ✅ Update database entry

        db['Toys'] = toys_dict  # ✅ Save changes

        toys_list = list(toys_dict.values())

        # Debugging output
        for toy in toys_list:
            print(f"🖼️ Debug - Toy: {toy.get_name()}, Image Path: {toy.get_image()}, Quantity: {toy.get_quantity()}")

    return render_template('retrieveToy.html', toys=toys_list)




@app.route('/toys/update/<int:id>', methods=['GET', 'POST'])
@staff_required
def update_toy(id):
    with shelve.open('toys.db', 'w') as db:
        toys_dict = db.get('Toys', {})
        toy = toys_dict.get(id)

        if not toy:
            flash("Toy not found.", "danger")
            return redirect(url_for('retrieve_toys'))

        if request.method == 'POST':
            # Only update fields that are filled
            if request.form['name']:
                toy.set_name(request.form['name'])
            if request.form['description']:
                toy.set_description(request.form['description'])
            if request.form['price']:
                toy.set_price(float(request.form['price']))
            if request.form['category']:
                toy.set_category(request.form['category'])

            # Handle Image Upload
            if 'image' in request.files and request.files['image'].filename != '':
                file = request.files['image']
                if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    toy.set_image(filename)

            toys_dict[id] = toy
            db['Toys'] = toys_dict
            flash("Toy updated successfully!", "success")
            return redirect(url_for('retrieve_toys'))

    return render_template('updateToy.html', toy=toy)




@app.route('/toys/set_quantity/<int:id>', methods=['POST'])
@staff_required
def set_toy_quantity(id):
    new_quantity = request.form.get('new_quantity', type=int)

    if new_quantity is None or new_quantity < 1:
        flash("Invalid quantity value.", "danger")
        return redirect(url_for('retrieve_toys'))

    with shelve.open('toys.db', 'w') as db:
        toys_dict = db.get('Toys', {})

        if id in toys_dict:
            toy = toys_dict[id]
            toy.set_quantity(new_quantity)
            toys_dict[id] = toy
            db['Toys'] = toys_dict  # ✅ Save changes

            # ✅ Debugging output
            print(f"🔢 Set Quantity: {toy.get_name()} - New Quantity: {toy.get_quantity()}")

    flash("Quantity updated successfully!", "success")
    return redirect(url_for('retrieve_toys'))


@app.route('/toys/update_quantity/<int:id>/<action>', methods=['POST'])
@staff_required
def update_toy_quantity(id, action):
    with shelve.open('toys.db', 'w') as db:
        toys_dict = db.get('Toys', {})

        if id in toys_dict:
            toy = toys_dict[id]

            if action == 'increase':
                toy.set_quantity(toy.get_quantity() + 1)
            elif action == 'decrease' and toy.get_quantity() > 1:
                toy.set_quantity(toy.get_quantity() - 1)

            toys_dict[id] = toy
            db['Toys'] = toys_dict  # ✅ Save changes to database

            # ✅ Debugging output
            print(f"🛒 Updated Quantity: {toy.get_name()} - New Quantity: {toy.get_quantity()}")

    return redirect(url_for('retrieve_toys'))


@app.route('/toys/delete/<int:id>', methods=['POST'])
@staff_required
def delete_toy(id):
    with shelve.open('toys.db', 'w') as db:
        toys_dict = db.get('Toys', {})
        if id in toys_dict:
            del toys_dict[id]
            db['Toys'] = toys_dict
            flash("Toy deleted successfully!", "success")
        else:
            flash("Toy not found.", "danger")
    return redirect(url_for('retrieve_toys'))


@app.route('/toys/<category>')
def view_category(category):
    with shelve.open('toys.db', 'c') as db:
        toys_dict = db.get('Toys', {})
        category_toys = [toy for toy in toys_dict.values() if toy.get_category() == category]
        print(f"Toys in category '{category}': {category_toys}")  # Debugging
    return render_template('category.html', category=category.capitalize(), toys=category_toys)



def calculate_average_rating(toy_id):
    with shelve.open('review.db', 'r') as db:
        reviews_dict = db.get('Reviews', {})

        # ✅ Filter reviews only for the specific toy_id
        toy_reviews = [review for review in reviews_dict.values() if review.get_toy_id() == toy_id]

        if toy_reviews:
            return sum(review.get_rating() for review in toy_reviews) / len(toy_reviews)
        else:
            return 0  # Default if no reviews exist


from transformers import pipeline

def summarize_reviews(reviews):
    """Summarizes the latest reviews using AI."""
    
    # ✅ Extract review comments
    text = " ".join([review.get_comment() for review in reviews if review.get_comment()])
    
    # ✅ If not enough text, return a default message
    if len(text) < 20:
        return "Not enough review content to summarize."

    # ✅ Initialize the Hugging Face summarizer
    summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

    # ✅ Generate summary
    summary = summarizer(text, max_length=100, min_length=30, do_sample=False)
    return summary[0]['summary_text']

@app.route('/toys/view/<int:id>')
def view_toy(id):
    with shelve.open('toys.db', 'c') as db:
        toys_dict = db.get('Toys', {})
        toy = toys_dict.get(id)
        if not toy:
            flash("Toy not found.", "danger")
            return redirect(url_for('catalog'))
    toy_id = id  # ✅ Ensure toy_id is explicitly defined

    # Fetch reviews for the toy
    with shelve.open('review.db', 'c') as db:
        reviews_dict = db.get('Reviews', {})
        reviews_list = [review for review in reviews_dict.values() if review.get_toy_id() == toy_id]

    # ✅ Ensure toy_id is passed correctly
    
    # ✅ Calculate average rating and total number of reviews
    average_rating = calculate_average_rating(toy_id)  # 🔹 Now toy_id is properly defined
    total_reviews = len(reviews_list)

    search_query = request.args.get('search_query', '')
    tag_filter = request.args.get('tag', '')

    # ✅ Apply search and tag filters
    if search_query:
        reviews_list = [review for review in reviews_list if search_query.lower() in review.get_comment().lower()]
    if tag_filter:
        reviews_list = [
            review for review in reviews_list 
            if tag_filter.lower() in [tag.lower() for tag in Review.extract_keywords(review.get_comment())]
        ]

    # ✅ Update global tags dynamically
    Review.update_global_tags(reviews_list)

    # ✅ AI Summary
    summary = summarize_reviews(reviews_list[:5])  # Call summarizer properly

    with shelve.open('qna.db', 'c') as db:
        qna_dict = db.get('QnA', {})
        qna_list = []
        for qna_entry in qna_dict.values():
            if not hasattr(qna_entry, "answers"):
                qna_entry.answers = []
            qna_list.append(qna_entry)

    active_tab = request.args.get('active_tab', 'reviews')
    Review.update_global_tags(reviews_list)
    global_tags = Review.global_tags if hasattr(Review, "global_tags") else []

    return render_template(
        'toy_details.html', 
        toy=toy, 
        reviews_list=reviews_list, 
        qna_list=qna_list, 
        summary=summary,
        average_rating=average_rating,  # ✅ Now correctly passed
        total_reviews=total_reviews, global_tags=global_tags
    )
 

@app.route('/toys/all')
def all_toys():
    with shelve.open('toys.db', 'c') as db:
        toys_dict = db.get('Toys', {})
        toys_list = list(toys_dict.values())
        for toy in toys_list:
            print(f"🖼️ Debug: {toy.get_name()} -> {toy.get_image()}")  # Check filenames
    return render_template('catalog.html', toys=toys_list)


@app.route('/debug/toys')
@staff_required
def debug_toys():
    with shelve.open('toys.db', 'c') as db:
        toys_dict = db.get('Toys', {})
        print("\n📦 Toy Inventory:")
        for toy_id, toy in toys_dict.items():
            print(f"🔹 {toy.get_name()} - Quantity: {toy.get_quantity()}")
    return "Check the Flask console for toy inventory."



def repair_user_db():
    try:
        with shelve.open('user.db', 'c') as db:
            users_dict = db.get('Users', {})
            repaired_dict = {}
            for user_id, user in users_dict.items():
                if isinstance(user_id, int) and isinstance(user, User.User):
                    repaired_dict[user_id] = user
                else:
                    print(f"Invalid entry found: {user_id} -> {user}")

            db['Users'] = repaired_dict
            print(f"Repaired user database. Users: {len(repaired_dict)}")
    except Exception as e:
        print(f"Error repairing database: {e}")









# ZOHRA
















@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'cart' not in session:
        session['cart'] = []

    data = request.get_json()
    item_name = data.get('name')
    item_price = float(data.get('price', 0.0))

    if not item_name or item_price <= 0:
        return jsonify({"message": "❌ Invalid item.", "status": "danger"}), 400

    existing_item = next((item for item in session['cart'] if item['name'].lower() == item_name.lower()), None)

    if existing_item:
        existing_item['quantity'] += 1
        existing_item['total_price'] = existing_item['quantity'] * existing_item['price']
    else:
        session['cart'].append({
            "name": item_name,
            "price": item_price,
            "quantity": 1,
            "total_price": item_price
        })

    session.modified = True
    return jsonify({"message": f"✅ {item_name} added to cart!", "status": "success"})


@app.route('/cart', methods=['GET'])
def cart():
    cart_items = session.get('cart', [])
    return render_template('cart.html', cart_items=cart_items)


@app.route('/update_cart', methods=['POST'])
def update_cart():
    if 'cart' not in session or not session['cart']:
        return jsonify({"message": "Cart is empty.", "status": "danger"}), 400

    data = request.get_json()
    action = data.get("action")
    item_name = data.get("name")

    if not action or not item_name:
        return jsonify({"message": "Invalid request.", "status": "danger"}), 400

    cart = session.get('cart', [])
    item = next((item for item in cart if item['name'].lower() == item_name.lower()), None)

    if not item:
        return jsonify({"message": "Item not found in cart.", "status": "danger"}), 400

    if action == "increase":
        item['quantity'] += 1
    elif action == "decrease":
        if item['quantity'] > 1:
            item['quantity'] -= 1
        else:
            cart.remove(item)  # Remove item if quantity reaches zero
    elif action == "remove":
        cart.remove(item)  # Fully remove the item
    else:
        return jsonify({"message": "Invalid action.", "status": "danger"}), 400

    # Recalculate total price after update
    item['total_price'] = item['quantity'] * item['price']

    session['cart'] = cart
    session.modified = True

    return jsonify({
        "message": "Cart updated successfully!",
        "status": "success",
        "cart": cart
    })

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    form = PaymentForm()  # Make sure form is initialized
    cart_items = session.get('cart', [])

    if not cart_items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('home'))

    total_price = sum(item.get('total_price', 0) for item in cart_items)

    if form.validate_on_submit():
        order = {
            'name': form.name.data,
            'email': form.email.data,
            'address': form.address.data,
            'total_price': total_price,
            'cart_items': cart_items,
            'order_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        session['last_order'] = order
        order_history = session.get('order_history', [])
        order_history.append(order)
        session['order_history'] = order_history
        session.pop('cart', None)
        session.modified = True

        return redirect(url_for('payment_success'))

    return render_template('checkout.html', form=form, cart_items=cart_items, total_price=total_price)


@app.route('/payment_success')
def payment_success():
    order = session.get('last_order')
    if not order:
        flash("No recent order found.", "warning")
        return redirect(url_for('home'))

    return render_template('payment_success.html', order=order)


@app.route('/retrievePayment', methods=['GET'])
def retrieve_payment():
    order_history = session.get('order_history', [])

    if not order_history:
        flash("⚠ No past orders found.", "warning")
        return redirect(url_for('home'))

    return render_template('retrievePayment.html', order_history=order_history)






#MELODY














@app.route('/listdiscounts')
def listdiscounts():
    with shelve.open('discount.db', 'c') as db:
        discounts_dict = db.get('Discounts', {})

    discounts_list = list(discounts_dict.values())  # Convert dict values to a list
    return render_template('listdiscounts.html', count=len(discounts_list), discounts_list=discounts_list)


# ✅ Create Discount
@app.route('/create_discount', methods=['GET', 'POST'])
def create_discount():
    form = CreateDiscountForm(request.form)

    if request.method == 'POST' and form.validate():
        with shelve.open('discount.db', 'c') as db:
            discount_dict = db.get('Discounts', {})

            # ✅ Create discount without user ID
            discount = Discount(
                form.name.data,
                form.percentage.data,
                form.startdate.data,
                form.enddate.data
            )

            discount_dict[discount.get_discount_id()] = discount
            db['Discounts'] = discount_dict  # ✅ Save back to shelve

        flash("Discount created successfully!", "success")
        return redirect(url_for('listdiscounts'))

    return render_template('create_discount.html', form=form)


# ✅ Update Discount
@app.route('/update_discount/<int:id>/', methods=['GET', 'POST'])
def update_discount(id):
    with shelve.open('discount.db', 'c') as db:
        discount_dict = db.get('Discounts', {})
        discount = discount_dict.get(id)

        if not discount:
            flash("Discount not found!", "danger")
            return redirect(url_for('listdiscounts'))

    form = CreateDiscountForm(request.form)

    if request.method == 'POST' and form.validate():
        with shelve.open('discount.db', 'w') as db:
            discount_dict = db['Discounts']
            discount = discount_dict[id]

            discount.set_name(form.name.data)
            discount.set_percentage(form.percentage.data)
            discount.set_startdate(form.startdate.data)
            discount.set_enddate(form.enddate.data)

            db['Discounts'] = discount_dict  # ✅ Save back to shelve

        flash("Discount updated successfully!", "success")
        return redirect(url_for('listdiscounts'))

    return render_template('update_discount.html', form=form, discount=discount)


# ✅ Delete Discount
@app.route('/delete_discount/<int:id>/', methods=['POST'])
def delete_discount(id):
    with shelve.open('discount.db', 'w') as db:
        discount_dict = db.get('Discounts', {})

        if id not in discount_dict:
            flash("Discount not found!", "danger")
            return redirect(url_for('listdiscounts'))

        del discount_dict[id]  # ✅ Delete the discount
        db['Discounts'] = discount_dict  # ✅ Save back to shelve

    flash("Discount deleted successfully!", "success")
    return redirect(url_for('listdiscounts'))

# Route for the chatbot page


@app.route('/chatbot', methods=['GET'])  # Only GET requests are allowed
def chatbot():
    return render_template('chatbot.html')  # Render the chatbot template

# Route to handle chatbot messages
@app.route('/chat', methods=['POST'])  # Only POST requests are allowed
def chat():
    user_message = request.json.get('message')
    responses = {
        "Send an email to customer service": "You can send an email to support@toysrus.com for assistance.",
        "Inquire about returns, refunds, and exchanges": "Our return policy allows returns within 30 days with a receipt. Please visit our Returns page for more details.",
        "Inquire about the Star Card Program": "The Star Card Program offers exclusive discounts and rewards. You can sign up at any ToysRUs store or online.",
        "Where can I use my promo code?": "Promo codes can be used during checkout on our website or in-store at the point of sale."
    }
    bot_response = responses.get(user_message, "I'm sorry, I don't understand that question. Please try one of the options above.")
    return jsonify({'response': bot_response})








#DENISE













@app.route('/createReview', methods=['GET', 'POST'])
def create_review():
    if 'user_id' not in session:
        flash('You need to be logged in to submit a review.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    toy_id = request.form.get('toy_id') or request.args.get('toy_id')

    if not toy_id:
        flash('No toy selected for review.', 'danger')
        return redirect(url_for('home'))

    try:
        toy_id = int(toy_id)
    except ValueError:
        flash('Invalid toy ID.', 'danger')
        return redirect(url_for('home'))

    # ✅ Fetch Toy Data
    with shelve.open('toys.db', 'c') as db:
        toys_dict = db.get('Toys', {})
        toy = toys_dict.get(toy_id)

    if not toy:
        flash('Toy not found.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        rating = request.form.get('rating')
        comment = request.form.get('comment')
        date = datetime.today().strftime('%Y-%m-%d')

        # ✅ Handle Image Upload
        image_path = None
        image_file = request.files.get('image')
        if image_file and image_file.filename:
            filename = secure_filename(image_file.filename)
            unique_filename = str(uuid.uuid4()) + os.path.splitext(filename)[1]
            image_path = os.path.join("static/images", unique_filename).replace("\\", "/")
            image_file.save(image_path)

        if not rating:
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('create_review', toy_id=toy_id))

        try:
            rating = int(rating)
        except ValueError:
            flash('Invalid rating format.', 'danger')
            return redirect(url_for('create_review', toy_id=toy_id))

        # ✅ Fetch User Data
        with shelve.open('user.db', 'c') as user_db:
            users_dict = user_db.get('Users', {})
            user = users_dict.get(str(user_id)) or users_dict.get(user_id)

        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('create_review', toy_id=toy_id))

        # ✅ Store Review in Database
        with shelve.open('review.db', 'c') as db:
            reviews_dict = db.get('Reviews', {})

            review_id = max(reviews_dict.keys(), default=0) + 1
            new_review = Review(user, rating, comment, date, review_id, toy_id, image_path)

            reviews_dict[review_id] = new_review
            db['Reviews'] = reviews_dict

        flash('Review submitted successfully!', 'success')
        return redirect(url_for('retrieve_reviews', toy_id=toy_id))

    return render_template('createReview.html', user_id=user_id, toy=toy)


# ✅ RETRIEVE REVIEWS WITH FIXED TAGS & QNA
@app.route('/retrieveReview', methods=['GET'])
def retrieve_reviews():
    search_query = request.args.get('search_query', '')
    tag_filter = request.args.get('tag', '')
    toy_id = request.args.get('toy_id')

    with shelve.open('review.db', 'c') as db:
        reviews_dict = db.get('Reviews', {})

        # ✅ Auto-fix missing `likes` attributes in old reviews
        updated = False
        for review_id, review in reviews_dict.items():
            if not hasattr(review, '_Review__likes'):
                review._Review__likes = 0
                review.liked_users = set()
                updated = True

        if updated:
            db['Reviews'] = reviews_dict

        reviews_list = list(reviews_dict.values())

    try:
        toy_id = int(toy_id)
    except (ValueError, TypeError):
        flash("Invalid toy ID.", "danger")
        return redirect(url_for('catalog'))

    # ✅ Fetch Toy Data
    with shelve.open('toys.db', 'c') as toy_db:
        toys_dict = toy_db.get('Toys', {})
        toy = toys_dict.get(toy_id)

    if not toy:
        flash("Toy not found.", "danger")
        return redirect(url_for('catalog'))

    # ✅ Filter by Toy ID
    reviews_list = [review for review in reviews_list if review.get_toy_id() == toy_id]

    if search_query:
        reviews_list = [review for review in reviews_list if search_query.lower() in review.get_comment().lower()]

    if tag_filter:
        reviews_list = [review for review in reviews_list if tag_filter.lower() in Review.extract_keywords(review.get_comment())]

    total_reviews = len(reviews_list)

    # ✅ Update Tags Dynamically
    Review.update_global_tags(reviews_list)
    global_tags = Review.global_tags if hasattr(Review, "global_tags") else []

    # ✅ Fetch QnA Data
    with shelve.open('qna.db', 'c') as qna_db:
        qna_dict = qna_db.get('QnA', {})
        qna_list = [qna for qna in qna_dict.values() if qna.get_toy_id() == toy_id]

    
    average_rating = calculate_average_rating(toy_id)

    return render_template(
        'toy_details.html',
        toy=toy,
        count=len(reviews_list),
        reviews_list=reviews_list,
        toy_id=toy_id,
        average_rating=average_rating,
        total_reviews=total_reviews, 
        global_tags=global_tags,  # ✅ Ensures tags display properly
        qna_list=qna_list  # ✅ Ensures QnA doesn't disappear
    )


# ✅ JSON ENDPOINT TO UPDATE TAGS WITHOUT PAGE RELOAD
@app.route('/get_tags/<int:toy_id>')
def get_tags(toy_id):
    # Fetch all reviews from the database
    with shelve.open('review.db', 'c') as db:
        reviews_dict = db.get('Reviews', {})

    # Filter the reviews to get only the ones for the specified toy_id
    reviews_list = [review for review in reviews_dict.values() if review.get_toy_id() == toy_id]

    # Update global tags based on these reviews
    Review.update_global_tags(reviews_list)

    # Make sure that Review.global_tags is properly populated
    global_tags = Review.global_tags if hasattr(Review, "global_tags") else []

    # Return the tags as JSON
    return jsonify({"tags": global_tags})





@app.route('/update_review', methods=['GET', 'POST'])
def update_review():
    if 'user_id' not in session:
        flash('You need to be logged in to update a review.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    review_id = request.args.get('review_id')  # Get from URL
    toy_id = request.args.get('toy_id')

    if not review_id or not toy_id:
        flash("Invalid request. Missing review or toy ID.", "danger")
        return redirect(url_for('catalog'))

    try:
        review_id = int(review_id)
        toy_id = int(toy_id)  # ✅ Convert to int
    except ValueError:
        flash("Invalid review or toy ID format.", "danger")
        return redirect(url_for('catalog'))

    # ✅ Retrieve review from `review.db`
    with shelve.open('review.db', 'c') as db:
        reviews_dict = db.get('Reviews', {})
        review = reviews_dict.get(review_id)

    if not review:
        flash("Review not found.", "danger")
        return redirect(url_for('catalog'))

    # ✅ Ensure the review belongs to the user & correct toy
    if str(review.get_user_id()) != str(user_id) or str(review.get_toy_id()) != str(toy_id):
        flash("You are not authorized to edit this review.", "danger")
        return redirect(url_for('catalog'))

    if request.method == 'POST':
        new_rating = request.form.get('rating')
        new_comment = request.form.get('comment')
        new_date = request.form.get('date')

        # ✅ Ensure all fields are filled
        if not new_rating or not new_date:
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for('update_review', review_id=review_id, toy_id=toy_id))

        try:
            new_rating = int(new_rating)
        except ValueError:
            flash("Invalid rating format.", "danger")
            return redirect(url_for('update_review', review_id=review_id, toy_id=toy_id))

        # ✅ Update review attributes
        review.set_rating(new_rating)
        review.set_comment(new_comment)
        review._Review__date = new_date  # ✅ Directly modifying the private attribute

        # ✅ Save changes
        with shelve.open('review.db', 'c') as db:
            reviews_dict = db.get('Reviews', {})
            reviews_dict[review_id] = review
            db['Reviews'] = reviews_dict

        flash("Review updated successfully!", "success")
        return redirect(url_for('retrieve_reviews', toy_id=toy_id))

    return render_template('updateReview.html', review=review, toy_id=toy_id)


@app.route('/deleteReview/', methods=['POST'])
def delete_review():
    if 'user_id' not in session:
        flash("You need to be logged in to delete a review.", "danger")
        return redirect(url_for('login'))

    user_id = str(session['user_id'])
    toy_id = request.form.get('toy_id')  # ✅ Get `toy_id` from form

    # ✅ Debugging: Check if toy_id is received
    print(f"DEBUG: Received toy_id -> {toy_id}")  
    print(f"DEBUG: Logged-in user_id -> {user_id}")

    if not toy_id:
        flash("Error: Missing toy ID.", "danger")
        return redirect(url_for('catalog'))  # Redirect to catalog if no toy_id

    with shelve.open('review.db', 'w') as db:
        reviews_dict = db.get('Reviews', {})

        print(f"DEBUG: Existing review keys -> {list(reviews_dict.keys())}")

        review_key = None
        for key, rev in reviews_dict.items():
            print(f"DEBUG: Checking review {key} -> User ID: {rev.get_user_id()}, Toy ID: {rev.get_toy_id()}")

            # ✅ FIX: Use `rev.get_toy_id()` instead of `rev.toy_id`
            if str(rev.get_user_id()) == user_id and str(rev.get_toy_id()) == str(toy_id):
                review_key = key
                break

        if review_key is not None:
            print(f"DEBUG: Deleting review with key {review_key}")
            del reviews_dict[review_key]
            db['Reviews'] = reviews_dict
            flash('Review deleted successfully!', 'success')
        else:
            flash('You do not have permission to delete this review.', 'danger')

    return redirect(url_for('retrieve_reviews', toy_id=toy_id))





@app.route('/like_review/<int:review_id>', methods=['POST'])
def like_review(review_id):
    if 'user_id' not in session:
        flash('You need to be logged in to like a review.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    toy_id = request.form.get('toy_id')

    print(f"DEBUG: User ID {user_id} is trying to like/unlike Review ID {review_id} for Toy ID {toy_id}")  # Debugging
    print(f"DEBUG: Form Data - {request.form}")  # Debugging

    with shelve.open('review.db', 'c') as db:
        reviews_dict = db.get('Reviews', {})
        review = reviews_dict.get(review_id)

        if not review:
            flash('Review not found.', 'danger')
            return redirect(url_for('retrieve_reviews', toy_id=toy_id))

        # Check if the user already liked the review
        if user_id in review.liked_users:
            print(f"DEBUG: User ID {user_id} is unliking Review ID {review_id}")  # Debugging
            review.unlike_review(user_id)
            flash('You unliked this review.', 'info')
        else:
            print(f"DEBUG: User ID {user_id} is liking Review ID {review_id}")  # Debugging
            review.like_review(user_id)
            flash('You liked this review!', 'success')

        print(f"DEBUG: Review ID {review_id} - Likes: {review.get_likes()}, Liked Users: {review.liked_users}")  # Debugging
        db['Reviews'] = reviews_dict

    return redirect(url_for('retrieve_reviews', toy_id=toy_id))


@app.route('/createFeedback', methods=['GET', 'POST'])
def create_feedback():
    if 'user_id' not in session:
        flash("You need to be logged in to submit feedback.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Retrieve user data
    with shelve.open('user.db', 'c') as user_db:
        users_dict = user_db.get('Users', {})
        user = users_dict.get(str(user_id)) or users_dict.get(user_id)

    if not user:
        flash("User not found. Please log in again.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        satisfactory = request.form.get('satisfactory')
        improvements = request.form.get('improvements')

        if not satisfactory or not improvements:
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for('create_feedback'))

        try:
            satisfactory = int(satisfactory)
        except ValueError:
            flash("Invalid rating format.", "danger")
            return redirect(url_for('create_feedback'))

        if len(improvements) < 20:
            flash("Feedback must be at least 20 characters long.", "danger")
            return redirect(url_for('create_feedback'))

        with shelve.open('feedback.db', 'c') as db:
            feedback_dict = db.get('Feedback', {})

            feedback_id = max(map(int, feedback_dict.keys()), default=0) + 1
            new_feedback = Feedback(user, satisfactory, improvements, feedback_id, date.today())

            feedback_dict[str(feedback_id)] = new_feedback
            db['Feedback'] = feedback_dict

        flash("Feedback submitted successfully!", "success")
        return redirect(url_for('home'))

    return render_template('createFeedback.html', user=user)




@app.route('/retrieveFeedback', methods=['GET'])
def retrieve_feedbacks():
    search_query = request.args.get('search_query', '')
    satisfaction_filter = request.args.get('satisfactory_filter', '')

    with shelve.open('feedback.db', 'c') as db:
        feedbacks_dict = db.get('Feedback', {})
        feedbacks_list = list(feedbacks_dict.values())

    # ✅ Fix search query
    if search_query:
        feedbacks_list = [feedback for feedback in feedbacks_list if search_query.lower() in feedback.improvements.lower()]

    # ✅ Fix satisfaction filter
    if satisfaction_filter:
        try:
            satisfaction_filter = int(satisfaction_filter)
            feedbacks_list = [feedback for feedback in feedbacks_list if feedback.satisfactory == satisfaction_filter]
        except ValueError:
            flash('Invalid satisfaction score filter.', 'danger')

    return render_template('retrieveFeedback.html', count=len(feedbacks_list), feedbacks_list=feedbacks_list, search_query=search_query, satisfaction_filter=satisfaction_filter)


@app.route('/exportFeedback')
def export_feedbacks():
    with shelve.open('feedback.db', 'c') as db:  # ✅ Use context manager
        feedbacks_dict = db.get('Feedback', {})  # ✅ Fix key to "Feedback"

        # ✅ Ensure all feedback objects have `date_posted`
        for feedback in feedbacks_dict.values():
            if not hasattr(feedback, 'date_posted'):
                feedback.date_posted = date.today()  # Assign today's date if missing
        db['Feedback'] = feedbacks_dict  # ✅ Save back to database

    feedbacks_list = list(feedbacks_dict.values())

    # ✅ Create CSV output
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['User ID', 'First Name', 'Last Name', 'Email', 'Satisfaction', 'Improvements', 'Date Posted'])

    for feedback in feedbacks_list:
        writer.writerow([
            feedback.get_user_id(), 
            feedback.get_first_name(), 
            feedback.get_last_name(),
            feedback.get_email(), 
            feedback.get_satisfactory(), 
            feedback.get_improvements(),
            feedback.get_date_posted()  # ✅ Include date
        ])

    output = si.getvalue()
    response = Response(output, mimetype="text/csv")
    response.headers['Content-Disposition'] = 'attachment; filename=feedbacks.csv'

    return response



@app.route('/deleteFeedback/<int:id>', methods=['POST'])
def delete_feedback(id):
    db = shelve.open('feedback.db', 'w')
    feedbacks_dict = db.get('Feedbacks', {})

    # Check if the feedback with the given ID exists
    if id in feedbacks_dict:
        del feedbacks_dict[id]
        db['Feedbacks'] = feedbacks_dict
        flash('Feedback deleted successfully!', 'success')
    else:
        flash('Feedback not found!', 'danger')

    db.close()
    return redirect(url_for('retrieve_feedbacks'))


@app.route('/create_qna', methods=['GET', 'POST'])
def create_qna():
    if 'user_id' not in session:
        flash('You need to be logged in to ask a question.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    toy_id = request.args.get('toy_id')

    if not toy_id:
        flash('No toy selected for Q&A.', 'danger')
        return redirect(url_for('home'))

    try:
        toy_id = int(toy_id)
    except ValueError:
        flash('Invalid toy ID.', 'danger')
        return redirect(url_for('home'))

    # Fetch user from `users.db`
    with shelve.open('user.db', 'c') as user_db:
        users_dict = user_db.get('Users', {})
        user = users_dict.get(user_id)  # Retrieve User instance

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('home'))

    # Fetch toy from `toys.db`
    with shelve.open('toys.db', 'c') as toy_db:
        toys_dict = toy_db.get('Toys', {})
        toy = toys_dict.get(toy_id)

    if not toy:
        flash("Toy not found.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        question = request.form.get('question')
        date_published = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Auto-set date

        if not question:
            flash("Please fill in all fields.", "danger")
            return redirect(url_for('create_qna', toy_id=toy_id))

        # Save Q&A to `qna.db`
        with shelve.open('qna.db', 'c') as db:
            qna_dict = db.get('QnA', {})

            print(f"DEBUG: Before Saving -> {qna_dict}")  

            qna_id = max(map(int, qna_dict.keys()), default=0) + 1  # Generate new qna_id
            new_qna = qna(user, toy_id, qna_id, question, date_published)  # Create new QnA object

            qna_dict[qna_id] = new_qna  # Add new QnA to the dictionary
            db['QnA'] = qna_dict  # Save updated dictionary to the database
            db.sync()  # Force changes to be written
        active_tab = request.args.get('active_tab', 'qna')  # Default to 'qna'
        flash("Question submitted successfully!", "success")
        return redirect(url_for('retrieve_qna', toy_id=toy_id))

    return render_template("createqna.html", user_id=user_id, toy=toy)

@app.route('/retrieve_qna', methods=['GET'])
def retrieve_qna():
    toy_id = request.args.get('toy_id')
    active_tab = request.args.get('active_tab', 'qna')

    try:
        toy_id = int(toy_id)
    except (ValueError, TypeError):
        flash("Invalid toy ID.", "danger")
        return redirect(url_for('catalog'))

    with shelve.open('toys.db', 'c') as toy_db:
        toys_dict = toy_db.get('Toys', {})
        toy = toys_dict.get(toy_id)

    if not toy:
        flash("Toy not found.", "danger")
        return redirect(url_for('catalog'))

    # ✅ Retrieve all QnA entries
    with shelve.open('qna.db', 'c') as db:
        qna_dict = db.get('QnA', {})
        qna_list = list(qna_dict.values())  # ✅ Extract stored objects, not dictionaries
    
    with shelve.open('review.db', 'c') as review_db:
        reviews_dict = review_db.get('Reviews', {})
        reviews_list = [review for review in reviews_dict.values() if review.get_toy_id() == toy_id]

    average_rating = calculate_average_rating(toy_id)

    # ✅ Filter QnA by toy_id
    qna_list = [qna_entry for qna_entry in qna_list if qna_entry.get_toy_id() == toy_id]
    for qna_entry in qna_list:
        print(f"DEBUG: QnA Entry Type: {type(qna_entry)}")
        print(f"DEBUG: QnA Entry Data: {qna_entry}")


    return render_template('toy_details.html', toy=toy, qna_list=qna_list, reviews_list=reviews_list, toy_id=toy_id, average_rating=average_rating)


@app.route('/create_qna_answer', methods=['POST'])
def create_qna_answer():
    if 'user_id' not in session:
        flash("You need to be logged in to answer a question.", "danger")
        return redirect(url_for('login'))

    qna_id = request.form.get('qna_id')  # Get QnA ID from form
    user_id = session['user_id']
    answer_text = request.form.get('answer_text')
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current date

    if not qna_id or not answer_text.strip():
        flash("Invalid QnA ID or empty answer!", "danger")
        return redirect(request.referrer)

    try:
        qna_id = int(qna_id)  # Convert QnA ID to integer
    except ValueError:
        flash("Invalid QnA ID format!", "danger")
        return redirect(request.referrer)

    with shelve.open('qna.db', writeback=True) as db:
        qna_dict = db.get('QnA', {})

        if qna_id in qna_dict:
            qna_entry = qna_dict[qna_id]

            # Ensure answers list exists in the QnA entry
            if not hasattr(qna_entry, "answers"):
                qna_entry.answers = []

            # Append the new answer
            qna_entry.answers.append({
                "user_id": user_id,
                "answer": answer_text,
                "date": date
            })

            db["QnA"] = qna_dict  # Save updated QnA dictionary
            db.sync()  # Ensure data is written to file

            flash("Answer submitted successfully!", "success")
        else:
            flash("QnA not found!", "danger")

    return redirect(request.referrer)


@app.route('/delete_qna', methods=['POST'])
def delete_qna():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "You need to be logged in to delete a QnA."})

    qna_id = request.form.get('qna_id')
    toy_id = request.form.get('toy_id')

    if not qna_id or not toy_id:
        return jsonify({"success": False, "error": "Missing QnA ID or Toy ID."})

    try:
        qna_id = int(qna_id)  # ✅ Convert to int (matches shelve keys)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid QnA ID format."})

    with shelve.open('qna.db', 'c') as db:
        qna_dict = db.get('QnA', {})

        print(f"🔍 Available QnA Keys in DB: {list(qna_dict.keys())}")  # ✅ Debugging

        # ✅ Convert all keys to integers (handles string/integer mismatches)
        qna_dict = {int(k): v for k, v in qna_dict.items()}

        if qna_id in qna_dict:
            del qna_dict[qna_id]  # ✅ Delete QnA
            db['QnA'] = qna_dict  # ✅ Save changes
            print(f"✅ Deleted QnA ID {qna_id}")
            return jsonify({"success": True})  # ✅ Return success response
        else:
            print(f"❌ QnA ID {qna_id} not found in DB!")
            return jsonify({"success": False, "error": "QnA not found."})





if __name__ == '__main__':
    app.run(debug=True)




