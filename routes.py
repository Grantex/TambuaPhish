from flask import (
    render_template, redirect, url_for, request, session, flash, current_app
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from models import db, User, CustomEmailTemplate
from forms import (
    RegistrationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm
)
from forms import CustomTemplateForm  # adjust the import path as necessary

from flask import Blueprint

routes_bp = Blueprint('routes', __name__)

# --- Helper: Send Email ---
def send_verification_email(to_email, subject, body_html):
    mail = current_app.extensions['mail']
    msg = Message(subject, recipients=[to_email], html=body_html)
    mail.send(msg)

# --- Serializer ---
def get_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])


# --- Landing Page ---
@routes_bp.route('/')
def landing():
    return render_template('index.html')


# --- Sign Up ---
@routes_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()

        s = get_serializer()
        token = s.dumps(new_user.email, salt='email-confirm')
        verification_link = url_for('routes.verify_email', token=token, _external=True)
        html_body = f"""
            <p>Hello {new_user.username},</p>
            <p>Welcome to TambuaPhish! Please verify your email by clicking below:</p>
            <p><a href="{verification_link}">Verify Email</a></p>
        """
        send_verification_email(new_user.email, "Verify Your Email - TambuaPhish", html_body)

        flash('Account created! Please check your email to verify.', 'success')
        return redirect(url_for('routes.login'))
    elif form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {field}: {error}", 'danger')
    return render_template('sign_up.html', form=form)


# --- Verify Email ---
@routes_bp.route('/verify/<token>')
def verify_email(token):
    s = get_serializer()
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('Verification link is invalid or has expired.', 'danger')
        return redirect(url_for('routes.login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.email_verified:
        flash('Your email is already verified.', 'info')
    else:
        user.email_verified = True
        db.session.commit()
        flash('Your email has been verified! You can now log in.', 'success')
    return redirect(url_for('routes.login'))


# --- Login ---
@routes_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            if not user.email_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('routes.login'))
            session['username'] = user.username
            session.permanent = True
            return redirect(url_for('routes.dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('log_in.html', form=form)


# --- Forgot Password ---
@routes_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            s = get_serializer()
            token = s.dumps(user.id, salt='password-reset-salt')
            reset_link = url_for('routes.reset_password', token=token, _external=True)
            html_body = f"""
                <p>Hello {user.username},</p>
                <p>You requested to reset your password. Click the link below to set a new password:</p>
                <p><a href="{reset_link}">Reset Password</a></p>
                <p>If you didn't request this, please ignore this email.</p>
            """
            send_verification_email(user.email, "Reset Your Password - TambuaPhish", html_body)
            flash(f'Password reset link sent to {form.email.data}.', 'info')
            return redirect(url_for('routes.login'))
        else:
            flash('No account associated with that email.', 'warning')
    return render_template('forgot_password.html', form=form)


# --- Reset Password ---
@routes_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    s = get_serializer()
    try:
        user_id = s.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('routes.forgot_password'))

    user = User.query.get_or_404(user_id)
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user.password_hash = hashed_password
        db.session.commit()
        flash('Your password has been reset successfully! You can now log in.', 'success')
        return redirect(url_for('routes.login'))
    return render_template('reset_password.html', form=form)


# --- Dashboard ---
@routes_bp.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('routes.login'))
    return render_template('dashboard.html', username=session['username'])


# --- Campaigns ---
@routes_bp.route('/campaigns')
def campaigns():
    if 'username' not in session:
        return redirect(url_for('routes.login'))
    return render_template('campaigns.html', username=session['username'])


# --- Close Campaign ---
@routes_bp.route('/close-campaign/<campaign_id>', methods=['POST'])
def close_campaign(campaign_id):
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    # Replace with your own data persistence logic
    for campaign in campaigns_data:
        if campaign['id'] == campaign_id:
            campaign['status'] = 'Completed'
            break

    return '', 204


# --- Phishing Templates ---
@routes_bp.route('/phishing-templates')
def phishing_templates():
    if 'username' not in session:
        return redirect(url_for('routes.login'))
    return render_template('templates.html', username=session['username'])


@routes_bp.route('/save-template', methods=['POST'])
def save_template():
    template_id = request.form.get('template_id')
    template_name = request.form.get('template_name')
    sender_name = request.form.get('sender_name')
    subject_line = request.form.get('subject_line')
    email_body = request.form.get('email_body')
    cta_link = request.form.get('cta_link')

    if template_id:
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
        existing = PhishingEmailTemplates.query.filter_by(template_name=template_name).first()
        if existing:
            flash('Template name already exists!', 'warning')
            return redirect(url_for('routes.phishing_templates'))

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

    return redirect(url_for('routes.phishing_templates'))


# --- Start Campaign ---
@routes_bp.route('/start-a-campaign')
def start_a_campaign():
    if 'username' not in session:
        return redirect(url_for('routes.login'))
    return render_template('start_campaign.html', username=session['username'])


@routes_bp.route('/create_custom_template', methods=['GET', 'POST'])
def create_custom_template():
    """
    Handle the creation of a custom email template.
    
    GET: Render the form for creating a new email template.
    POST: Process the form submission and save the template to the database.

    Form fields expected:
        - template_name: str, required
        - sender_name: str, required
        - subject: str, required
        - email_body: str, required
        - cta_link: str, optional
        - action: str, either 'save' or 'launch'

    On successful save:
        - If action is 'save', redirect to dashboard.
        - If action is 'launch', redirect to launch campaign page.
    """

    if request.method == 'POST':
        # Extract form data
        template_name = request.form.get('template_name')
        sender_name = request.form.get('sender_name')
        subject_line = request.form.get('subject')
        body = request.form.get('email_body')
        cta_link = request.form.get('cta_link')  # optional
        action = request.form.get('action')  # expected: 'save' or 'launch'

        # Simple validation (could be enhanced)
        if not all([template_name, sender_name, subject_line, body]):
            flash('All required fields must be filled out.', 'danger')
            return render_template('inlined_create_custom_template.html')

        try:
            # Create template instance
            new_template = CustomEmailTemplate(
                template_name=template_name,
                sender_name=sender_name,
                subject_line=subject_line,
                body=body,
                cta_link=cta_link
            )

            # Save to DB
            db.session.add(new_template)
            db.session.commit()

            flash('Template saved successfully!', 'success')

            # Redirect based on user action
            if action == 'save':
                return redirect(url_for('routes.dashboard'))
            elif action == 'launch':
                return redirect(url_for('routes.launch_campaign'))
            else:
                flash('Unknown action submitted.', 'warning')

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while saving the template: {str(e)}', 'danger')

    # Render the form
    return render_template('inlined_create_custom_template.html')


# --- Training Modules ---
@routes_bp.route('/training-modules')
def training_modules():
    if 'username' not in session:
        return redirect(url_for('routes.login'))
    return render_template('training_modules.html', username=session['username'])


# --- Logout ---
@routes_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('routes.landing'))