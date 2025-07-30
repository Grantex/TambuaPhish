from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Regexp
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

#from main import app, db
#from main import PhishingEmailTemplates

app = Flask(__name__)

# SQLite Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tambuaphish.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Session and Security Config
app.secret_key = 'your-very-secure-secret-key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
csrf = CSRFProtect(app)

serializer = URLSafeTimedSerializer(app.secret_key)


# ---- Zoho SMTP Config ----
app.config['MAIL_SERVER'] = 'smtp.zoho.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'info@tambuaphish.store'
app.config['MAIL_PASSWORD'] = '7Vx4X8Khg6h1'
app.config['MAIL_DEFAULT_SENDER'] = ('TambuaPhish', 'info@tambuaphish.store')

mail = Mail(app)

# Token serializer for secure verification & reset links
s = URLSafeTimedSerializer(app.secret_key)

# ---- User Model ----
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)  # NEW

# ---- Forms ----
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=12, message='Password must be at least 12 characters long.'),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).*$',
               message='Password must include uppercase, lowercase, numbers, and special characters.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_password(self, password):
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'user', 'iloveyou']
        if password.data.lower() in common_passwords:
            raise ValidationError('Your password is too common. Please choose a stronger one.')
        if self.username.data.lower() in password.data.lower():
            raise ValidationError('Your password cannot contain your username.')
        if self.email.data.lower().split('@')[0] in password.data.lower():
            raise ValidationError('Your password cannot contain part of your email.')

    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError('That email is already registered.')

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('That username is already taken.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=12, message='Password must be at least 12 characters long.'),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).*$',
               message='Password must include uppercase, lowercase, numbers, and special characters.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Reset Password')

# ---- Template Creation Model ----
class PhishingEmailTemplates(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    template_name = db.Column(db.String(100), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False)
    subject_line = db.Column(db.String(200), nullable=False)
    email_body = db.Column(db.Text, nullable=False)  # Supports large text
    cta_link = db.Column(db.String(300), nullable=False)

    def __repr__(self):
        return f'<PhishingEmailTemplates {self.template_name}>'
    

# ---- Email Sending Function ----
def send_verification_email(to_email, subject, body_html):
    msg = Message(subject, recipients=[to_email], html=body_html)
    mail.send(msg)

# ---- Routes ----
@app.route('/')
def landing():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        token = s.dumps(new_user.email, salt='email-confirm')
        verification_link = url_for('verify_email', token=token, _external=True)
        html_body = f"""
            <p>Hello {new_user.username},</p>
            <p>Welcome to TambuaPhish! Please verify your email by clicking below:</p>
            <p><a href="{verification_link}">Verify Email</a></p>
        """
        send_verification_email(new_user.email, "Verify Your Email - TambuaPhish", html_body)

        flash('Account created! Please check your email to verify.', 'success')
        return redirect(url_for('login'))
    elif form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {field}: {error}", 'danger')
    return render_template('sign_up.html', form=form)

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except Exception:
        flash('Verification link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.email_verified:
        flash('Your email is already verified.', 'info')
    else:
        user.email_verified = True
        db.session.commit()
        flash('Your email has been verified! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            if not user.email_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))
            session['username'] = user.username
            session.permanent = True
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('log_in.html', form=form)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = serializer.dumps(user.id, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)
            html_body = f"""
                <p>Hello {user.username},</p>
                <p>You requested to reset your password. Click the link below to set a new password:</p>
                <p><a href="{reset_link}">Reset Password</a></p>
                <p>If you didn't request this, please ignore this email.</p>
            """
            send_verification_email(user.email, "Reset Your Password - TambuaPhish", html_body)
            flash(f'Password reset link sent to {form.email.data}.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account associated with that email.', 'warning')
    return render_template('forgot_password.html', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        user_id = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # token valid for 1 hour
    except Exception:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.get_or_404(user_id)
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user.password_hash = hashed_password
        db.session.commit()
        flash('Your password has been reset successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/campaigns')
def campaigns():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('campaigns.html', username=session['username'])

#Sub-route in Campaigns section

@app.route('/close-campaign/<campaign_id>', methods=['POST'])
def close_campaign(campaign_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Replace with your own data persistence method
    for campaign in campaigns_data:
        if campaign['id'] == campaign_id:
            campaign['status'] = 'Completed'
            break

    return '', 204  # No Content
#----------------------------------------------------------------------

@app.route('/phishing templates')
def phishing_templates():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('templates.html', username=session['username'])


@app.route('/save-template', methods=['POST'])
def save_template():
    template_id = request.form.get('template_id')  # hidden field in form if editing
    template_name = request.form.get('template_name')
    sender_name = request.form.get('sender_name')
    subject_line = request.form.get('subject_line')
    email_body = request.form.get('email_body')
    cta_link = request.form.get('cta_link')

    if template_id:
        # Update existing template
        template = PhishingEmailTemplates.query.get(template_id)
        if template:
            template.template_name = template_name
            template.sender_name = sender_name
            template.subject_line = subject_line
            template.email_body = email_body
            template.cta_link = cta_link
            db.session.commit()
            flash('Template updated successfully!', 'success')
        else:
            flash('Template not found!', 'danger')
    else:
        # Create new template
        new_template = PhishingEmailTemplates(
            template_name=template_name,
            sender_name=sender_name,
            subject_line=subject_line,
            email_body=email_body,
            cta_link=cta_link
        )
        db.session.add(new_template)
        db.session.commit()
        flash('Template created successfully!', 'success')

    return redirect(url_for('phishing templates'))  # Replace with your actual template list route

#--------------------------------------------------------------------------

@app.route('/start a campaign')
def start_a_campaign():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('start_campaign.html', username=session['username'])

#Routes in start a campaign page and functions

@app.route('/create_custom_template', methods=['GET', 'POST'])
def create_custom_template():
    if request.method == 'POST':
        # Get form data
        template_name = request.form['template_name']
        sender_name = request.form['sender_name']
        sender_email = request.form['sender_email']
        subject = request.form['subject']
        body = request.form['email_body']
        cta_link = request.form.get('cta_link')
        action = request.form.get('action')  # Get which button was clicked

        # Save the template (simulated here, adapt to your DB/file logic)
        # Example: new_template_id = save_template_to_db(...)

        flash('Template saved successfully!', 'success')

        if action == 'save':
            return redirect(url_for('dashboard'))  # or template list page
        elif action == 'launch':
            # Redirect to a launch campaign route, possibly with the template info
            # You can pass the template name or ID if needed
            return redirect(url_for('launch_campaign'))  # update as needed

    return render_template('inlined_create_custom_template.html')

#-----------------------------------------------------

@app.route('/training modules')
def training_modules():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('training_modules.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)