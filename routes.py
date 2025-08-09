from flask import (
    render_template, redirect, url_for, request, session, flash, current_app
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from models import db, User, CustomEmailTemplate, Campaign, Recipient
from forms import (
    RegistrationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm
)

from flask import Blueprint
from flask_wtf.csrf import generate_csrf
from flask import jsonify
from datetime import datetime
from phishing_email_function import send_phishing_email
from flask import session
from models import User

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

            # ✅ Store both username and user_id in session
            session['username'] = user.username
            session['user_id'] = user.id
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
from datetime import datetime
from flask import render_template, redirect, url_for, session, request
from models import Campaign
from sqlalchemy.orm import joinedload



@routes_bp.route('/campaigns')
def campaigns():
    if 'username' not in session:
        return redirect(url_for('routes.login'))
    
    # Eager load recipients so they are ready for the template
    all_campaigns = Campaign.query.options(
        joinedload(Campaign.recipients)
    ).order_by(Campaign.start_date.desc()).all()

    return render_template(
        'campaigns.html',
        username=session['username'],
        campaigns=all_campaigns
    )





@routes_bp.route("/api/campaigns")
def get_campaigns():
    campaigns = Campaign.query.filter_by(user_id=session["username"]).all()
    result = []

    for campaign in campaigns:
        recipients = Recipient.query.filter_by(campaign_id=campaign.id).all()

        total_recipients = len(recipients)
        clicks = sum(1 for r in recipients if r.has_clicked)
        click_rate = round((clicks / total_recipients) * 100, 2) if total_recipients > 0 else 0

        result.append({
            "id": campaign.id,
            "name": campaign.name,
            "description": campaign.description,
            "status": campaign.status,
            "start_date": campaign.start_date.isoformat() if campaign.start_date else None,
            "end_date": campaign.end_date.isoformat() if campaign.end_date else None,
            "total_recipients": total_recipients,
            "clicks": clicks,
            "click_rate": f"{click_rate}%",
            "recipients": [
                {
                    "email": r.email,
                    "has_clicked": r.has_clicked,
                    "clicked_at": r.clicked_at.isoformat() if r.clicked_at else None
                } for r in recipients
            ]
        })

    return jsonify(result)



from datetime import datetime

@routes_bp.route('/track-link/<int:campaign_id>/<int:recipient_id>')
def track_link(campaign_id, recipient_id):
    recipient = Recipient.query.filter_by(
        id=recipient_id,
        campaign_id=campaign_id
    ).first()

    if recipient:
        # Only mark first click (if you want to avoid overwriting)
        if not recipient.has_clicked:
            recipient.has_clicked = True
            recipient.clicked_at = datetime.utcnow()
            db.session.commit()

    # Redirect to a landing page (can be awareness page, fake login, etc.)
    return redirect(url_for('routes.phish_landing'))


@routes_bp.route('/phish-landing')
def phish_landing():
    return render_template('phish_busted.html')


# --- Close Campaign ---
@routes_bp.route('/close-campaign/<int:campaign_id>', methods=['POST'])
def close_campaign(campaign_id):
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.status = "Completed"
    campaign.end_date = datetime.utcnow()

    db.session.commit()

    return redirect(url_for('routes.campaigns'))



# --- Phishing Templates ---

@routes_bp.route('/phishing-templates')
def phishing_templates():
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    current_user = User.query.filter_by(username=session['username']).first()

    if not current_user:
        flash('User not found.', 'danger')
        return redirect(url_for('routes.login'))

    templates = CustomEmailTemplate.query.filter_by(user_id=current_user.id).all()
    
    return render_template('templates.html', templates=templates)

#----------Preview Templates-----------

@routes_bp.route('/preview-template/<int:template_id>')
def preview_template(template_id):
    if 'user_id' not in session:
        flash('You must be logged in to preview templates.', 'danger')
        return redirect(url_for('routes.login'))

    template = CustomEmailTemplate.query.filter_by(id=template_id, user_id=session['user_id']).first()

    if not template:
        flash('Template not found or access denied.', 'danger')
        return redirect(url_for('routes.phishing_templates'))

    return render_template('preview_templates.html', template=template)

#------Edit Template-------------------

from flask import render_template, request, redirect, url_for, session, flash
from models import db, CustomEmailTemplate

@routes_bp.route('/edit-template/<int:template_id>', methods=['GET', 'POST'])
def edit_template(template_id):
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    template = CustomEmailTemplate.query.get_or_404(template_id)
    
    # Check ownership
    if template.user_id != session['user_id']:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('routes.dashboard'))

    form = EditTemplateForm()

    if form.validate_on_submit():
        template.template_name = form.template_name.data
        template.sender_name = form.sender_name.data
        template.subject = form.subject.data
        template.email_body = form.email_body.data
        db.session.commit()
        flash("Template updated successfully.", "success")
        return redirect(url_for('routes.dashboard'))

    # Pre-fill form only on GET
    if request.method == 'GET':
        form.template_name.data = template.template_name
        form.sender_name.data = template.sender_name
        form.subject.data = template.subject
        form.email_body.data = template.email_body

    return render_template('edit.html', form=form, template=template)

#----Delete Template----------------

@routes_bp.route('/delete-template/<int:template_id>', methods=['POST'])
def delete_template(template_id):
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    template = CustomEmailTemplate.query.filter_by(id=template_id, user_id=session['user_id']).first()

    if not template:
        flash('Template not found or unauthorized access.', 'danger')
        return redirect(url_for('routes.phishing_templates'))

    db.session.delete(template)
    db.session.commit()
    flash('Template deleted successfully.', 'success')
    return redirect(url_for('routes.phishing_templates'))


# --- Start Campaign ---
   

@routes_bp.route('/start-a-campaign', methods=['GET', 'POST'])
def start_a_campaign():
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    user = User.query.filter_by(username=session['username']).first()
    templates = CustomEmailTemplate.query.filter_by(user_id=user.id).all()

    if request.method == 'POST':
        campaign_name = request.form.get('campaign_name')
        campaign_description = request.form.get('campaign_description')
        target_emails_raw = request.form.get('target_emails')
        selected_template_id = request.form.get('selected_template_id')

        # 🚀 Save & Launch path
        if 'save_and_launch' in request.form:
            if not campaign_name or not campaign_description or not target_emails_raw:
                flash("Please fill all campaign fields before creating a template to launch.", "danger")
                return redirect(url_for('routes.start_a_campaign'))

            session['pending_campaign'] = {
                'campaign_name': campaign_name,
                'campaign_description': campaign_description,
                'target_emails': target_emails_raw
            }
            return redirect(url_for('routes.create_custom_template'))

        # 🟢 Normal Launch path
        if not campaign_name or not campaign_description or not target_emails_raw or not selected_template_id:
            flash("All campaign fields must be filled before launching.", "danger")
            return redirect(url_for('routes.start_a_campaign'))

        target_emails = [email.strip() for email in target_emails_raw.split(',') if email.strip()]

        # ✅ Create campaign
        new_campaign = Campaign(
            name=campaign_name.strip(),
            description=campaign_description.strip(),
            template_id=selected_template_id,
            user_id=session['username']  # ✅ store actual user.id, not username
        )
        db.session.add(new_campaign)
        db.session.commit()  # commit so campaign_id exists

        # ✅ Create recipients
        recipients = []
        for email in target_emails:
            recipient = Recipient(email=email, campaign_id=new_campaign.id)
            db.session.add(recipient)
            recipients.append(recipient)
        db.session.commit()  # commit so recipient IDs exist

        # ✅ Load email template
        template = CustomEmailTemplate.query.get(selected_template_id)

        # ✅ Send emails using real recipient IDs
        for recipient in recipients:
            send_phishing_email(recipient.email, template, new_campaign.id, recipient.id)

        flash('Campaign launched and phishing emails sent successfully!', 'success')
        return redirect(url_for('routes.campaigns'))

    # Just visiting the page
    pending_campaign = session.pop('pending_campaign', None)
    csrf_token = generate_csrf()

    return render_template(
        'start_campaign.html',
        username=session['username'],
        templates=templates,
        csrf_token=csrf_token,
        pending_campaign=pending_campaign
    )


#-----------------------------------------------------------------------------


from flask import session, redirect, url_for


@routes_bp.route('/create-custom-template', methods=['GET', 'POST'])
def create_custom_template():
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('routes.login'))

    if request.method == 'POST':
        template_name = request.form['template_name']
        sender_name = request.form['sender_name']
        subject = request.form['subject']
        email_body = request.form['email_body']

        user = User.query.filter_by(username=session['username']).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('routes.login'))

        template = CustomEmailTemplate(
            user_id=user.id,
            template_name=template_name,
            sender_name=sender_name,
            subject=subject,
            email_body=email_body
        )
        db.session.add(template)
        db.session.commit()

        # 🚀 If Save & Launch, create campaign now
        if 'save_and_launch' in request.form:
            campaign_name = request.form.get('campaign_name')
            campaign_description = request.form.get('campaign_description')
            target_emails_raw = request.form.get('target_emails')

            if not campaign_name or not campaign_description or not target_emails_raw:
                flash('Missing campaign data. Please start again.', 'danger')
                return redirect(url_for('routes.start_a_campaign'))

            # ✅ Assign campaign to the logged-in user
            new_campaign = Campaign(
                user_id=session['user_id'],  # <-- IMPORTANT
                name=campaign_name,
                description=campaign_description,
                template_id=template.id
            )
            db.session.add(new_campaign)
            db.session.commit()

            target_emails = [email.strip() for email in target_emails_raw.split(',') if email.strip()]
            for email in target_emails:
                db.session.add(Target(email=email, campaign_id=new_campaign.id))
            db.session.commit()

            flash('Template saved and campaign launched successfully!', 'success')
            return redirect(url_for('routes.campaigns'))

        flash('Template saved successfully!', 'success')
        return redirect(url_for('routes.phishing_templates'))

    # Prefill from session if exists
    pending_campaign = session.get('pending_campaign', {})
    return render_template(
        'inlined_create_custom_template.html',
        campaign_name=pending_campaign.get('campaign_name', ''),
        campaign_description=pending_campaign.get('campaign_description', ''),
        target_emails=pending_campaign.get('target_emails', '')
    )


#-----Actual Launching of Campaigns-------------

@routes_bp.route('/launch-campaign', methods=['GET', 'POST'])
def launch_campaign():
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    if request.method == 'POST':
        name = request.form.get('campaign_name', '').strip()
        description = request.form.get('campaign_description', '').strip()
        template_id = request.form.get('selected_template_id', '').strip()
        target_emails_raw = request.form.get('target_emails', '')

        # Validate
        if not name or not description or not template_id or not target_emails_raw:
            flash("All campaign fields are required.", "danger")
            return redirect(url_for('routes.launch_campaign'))

        target_emails = [e.strip() for e in target_emails_raw.splitlines() if e.strip()]

        # Create campaign
        campaign = Campaign(
            name=name,
            description=description,
            template_id=template_id
        )
        db.session.add(campaign)
        db.session.commit()  # Commit so we have campaign.id

        # Create recipients + send emails
        for email in target_emails:
            recipient = Recipient(email=email, campaign_id=campaign.id)
            db.session.add(recipient)
            db.session.flush()  # Get recipient.id without full commit

            # Generate unique tracking link per recipient
            tracking_link = f"{request.url_root}track/{campaign.id}/{recipient.id}"

            # Send phishing email with tracking
            send_phishing_email(email, template_id, tracking_link)

        db.session.commit()

        flash("Campaign launched and emails sent!", "success")
        return redirect(url_for('routes.campaigns'))

    # GET request
    templates = CustomEmailTemplate.query.all()
    return render_template('launch_campaign.html', templates=templates)



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