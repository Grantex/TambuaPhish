from flask import (
    render_template, redirect, url_for, request, session, flash, current_app
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from models import db, User, CustomEmailTemplate, Campaign, Recipient, TrainingModule, Assignment
from forms import (
    RegistrationForm, LoginForm,ForgotPasswordForm, ResetPasswordForm, EditTemplateForm, TrainingModuleForm, AssignForm
)

from flask import Blueprint, render_template, url_for, send_file
from flask_wtf.csrf import generate_csrf, CSRFProtect
from flask import jsonify
from datetime import datetime
from phishing_email_function import send_phishing_email
from training_assignment_email_function import send_assignment_email
from flask import session
from models import User
import json
import tempfile
from playwright.sync_api import sync_playwright
from sqlalchemy.orm import joinedload


routes_bp = Blueprint('routes', __name__)

csrf = CSRFProtect()


# --- Send verification Email ---
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

            # Store both username and user_id in session
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

    username = session['username']

    # Campaign & recipient counts filtered by username
    user_campaigns = Campaign.query.filter_by(user_id=username).all()
    total_campaigns = len(user_campaigns)

    total_recipients = Recipient.query.join(Campaign).filter(Campaign.user_id == username).count()
    total_clicks = Recipient.query.join(Campaign).filter(
        Campaign.user_id == username,
        Recipient.has_clicked == True
    ).count()

    ctr = (total_clicks / total_recipients * 100) if total_recipients > 0 else 0

    # Build dynamic monthly data stats
    monthly_emails_sent = []
    monthly_ctr = []

    for month in range(1, 13):
        month_recipients = Recipient.query.join(Campaign).filter(
            Campaign.user_id == username,
            db.extract('month', Recipient.sent_at) == month
        ).count()

        month_clicks = Recipient.query.join(Campaign).filter(
            Campaign.user_id == username,
            db.extract('month', Recipient.sent_at) == month,
            Recipient.has_clicked == True
        ).count()

        monthly_emails_sent.append(month_recipients)
        monthly_ctr.append((month_clicks / month_recipients * 100) if month_recipients > 0 else 0)

    return render_template(
        'dashboard.html',
        username=username,
        total_campaigns=total_campaigns,
        total_recipients=total_recipients,
        total_clicks=total_clicks,
        ctr=round(ctr, 1),
        monthly_emails_sent=monthly_emails_sent,
        monthly_ctr=monthly_ctr
    )



# --- Campaigns ---


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
    if 'username' not in session:
        return redirect(url_for('routes.login'))
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


# Close campaign route


@routes_bp.route("/close-campaign/<int:campaign_id>", methods=["POST"])
def close_campaign(campaign_id):
    if "username" not in session:
        flash("Not logged in", "error")
        return redirect(url_for("routes.get_campaigns"))

    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        flash("User not found", "error")
        return redirect(url_for("routes.get_campaigns"))

    campaign = Campaign.query.get(campaign_id)
    if not campaign or campaign.user_id != session['username']:
        flash("Campaign not found or unauthorized", "error")
        return redirect(url_for("routes.get_campaigns"))

    campaign.mark_completed()
    db.session.commit()

    flash("Campaign closed successfully", "success")
    return redirect(url_for("routes.get_campaigns"))



# Delete Campaign Route
@routes_bp.route("/api/campaigns/<int:campaign_id>", methods=["DELETE"])
def delete_campaign_api(campaign_id):
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    campaign = Campaign.query.filter_by(id=campaign_id, user_id=session['username']).first()
    if not campaign:
        return jsonify({"error": "Campaign not found or unauthorized"}), 404
        
    try:
        db.session.delete(campaign)
        db.session.commit()
        return jsonify({"message": "Campaign deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to delete campaign: {str(e)}"}), 500

#------------Campaign Report-------------------------------------

@routes_bp.route("/campaign/<int:campaign_id>/report")
def view_report(campaign_id):
    is_pdf = request.args.get("pdf", "0") == "1"

    # Only enforce login if not rendering for PDF
    if not session.get('username') and not is_pdf:
        return redirect('/login')

    # Fetch campaign or 404
    campaign = Campaign.query.get_or_404(campaign_id)

    # Resolve owner: use campaign.user if available, else fallback to session username
    resolved_owner = (
        campaign.user.username if campaign.user
        else session.get('username') or request.args.get('username', 'Unknown')
    )

    # Metrics
    total_recipients = Recipient.query.filter_by(campaign_id=campaign_id).count()
    total_clicks = Recipient.query.filter_by(campaign_id=campaign_id, has_clicked=True).count()
    ctr = round((total_clicks / total_recipients) * 100, 2) if total_recipients > 0 else 0

    metrics = {
        "total_recipients": total_recipients,
        "total_clicks": total_clicks,
        "ctr": ctr
    }

    # Recipient activity breakdown
    recipients = Recipient.query.filter_by(campaign_id=campaign_id).all()
    recipient_data = []
    for r in recipients:
        if r.has_clicked and r.clicked_at:
            status = "Clicked"
            timestamp = r.clicked_at.strftime("%b %d %Y %I:%M %p")
        else:
            status = "Not Clicked"
            timestamp = None

        recipient_data.append({
            "email": r.email,
            "status": status,
            "timestamp": timestamp
        })

    # Timeline data
    clicks_by_date = {}
    for r in recipients:
        if r.has_clicked and r.clicked_at:
            date_str = r.clicked_at.strftime("%b %d %Y")
            clicks_by_date[date_str] = clicks_by_date.get(date_str, 0) + 1

    timeline_labels = list(clicks_by_date.keys())
    timeline_data = list(clicks_by_date.values())

    return render_template(
        "report.html",
        campaign={
            "id": campaign.id,
            "name": campaign.name,
            "description": campaign.description,
            "status": campaign.status,
            "start_date": campaign.start_date.strftime("%b %d %Y"),
            "end_date": campaign.end_date.strftime("%b %d %Y") if campaign.end_date else None,
            "owner": resolved_owner,
            "template_name": campaign.template.template_name if campaign.template else "Unknown"
        },
        metrics=metrics,
        recipients=recipient_data,
        timeline={"labels": json.dumps(timeline_labels), "data": json.dumps(timeline_data)},
        is_pdf=is_pdf
    )



@routes_bp.route("/campaign/<int:campaign_id>/report/download")
def download_report(campaign_id):
    # Generate PDF using Playwright
    url = url_for("routes.view_report", campaign_id=campaign_id, _external=True) + f"?pdf=1&username={session.get('username')}"


    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url, wait_until="networkidle")
        # Export to a temporary PDF
        tmp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        page.pdf(path=tmp_pdf.name, format="A4")
        browser.close()

    return send_file(tmp_pdf.name, as_attachment=True, download_name=f"campaign_{campaign_id}_report.pdf")


#-----------------------------------------------------------------------------------------------------------


@routes_bp.route('/track-link/<int:campaign_id>/<int:recipient_id>')
def track_link(campaign_id, recipient_id):
    recipient = Recipient.query.filter_by(
        id=recipient_id,
        campaign_id=campaign_id
    ).first()

    if recipient:
        # Only captures first click 
        if not recipient.has_clicked:
            recipient.has_clicked = True
            recipient.clicked_at = datetime.utcnow()
            db.session.commit()

    # Redirect to a landing page (can be awareness page, fake login, etc.)
    return redirect(url_for('routes.phish_landing'))


@routes_bp.route('/phish-landing')
def phish_landing():
    return render_template('phish_busted.html')



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
        return redirect(url_for('routes.phishing_templates'))

    # Pre-fill form only on GET
    if request.method == 'GET':
        form.template_name.data = template.template_name
        form.sender_name.data = template.sender_name
        form.subject.data = template.subject
        form.email_body.data = template.email_body

    return render_template('edit_template.html', form=form, template=template)

#----Delete Template----------------

@routes_bp.route('/delete-template/<int:template_id>', methods=['POST'])
def delete_template(template_id):
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    template = CustomEmailTemplate.query.get_or_404(template_id)

    # Check ownership
    if template.user_id != session['user_id']:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('routes.phishing_templates'))

    # Check if campaigns use it
    campaigns_using = Campaign.query.filter_by(template_id=template.id).count()
    if campaigns_using > 0:
        flash("This template is used in existing campaigns and cannot be deleted.", "danger")
        return redirect(url_for('routes.phishing_templates'))

    db.session.delete(template)
    db.session.commit()
    flash("Template deleted successfully.", "success")
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

        # Save & Launch path
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

        # Normal Launch path
        if not campaign_name or not campaign_description or not target_emails_raw or not selected_template_id:
            flash("All campaign fields must be filled before launching.", "danger")
            return redirect(url_for('routes.start_a_campaign'))

        target_emails = [email.strip() for email in target_emails_raw.split(',') if email.strip()]

        # Create campaign
        new_campaign = Campaign(
            name=campaign_name.strip(),
            description=campaign_description.strip(),
            template_id=selected_template_id,
            user_id=session['username']  
        )
        db.session.add(new_campaign)
        db.session.commit()  # commit so campaign_id exists

        # Creates recipients
        recipients = []
        for email in target_emails:
            recipient = Recipient(email=email, campaign_id=new_campaign.id)
            db.session.add(recipient)
            recipients.append(recipient)
        db.session.commit()  # commit so recipient IDs exist

        # Load phishing email template
        template = CustomEmailTemplate.query.get(selected_template_id)

        # Send emails using real recipient IDs
        for recipient in recipients:
            send_phishing_email(recipient.email, template, new_campaign.id, recipient.id)

        flash('Campaign launched and phishing emails sent successfully!', 'success')
        return redirect(url_for('routes.campaigns'))

 
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

        # If Save & Launch, create campaign now
        if 'save_and_launch' in request.form:
            campaign_name = request.form.get('campaign_name')
            campaign_description = request.form.get('campaign_description')
            target_emails_raw = request.form.get('target_emails')

            if not campaign_name or not campaign_description or not target_emails_raw:
                flash('Missing campaign data. Please start again.', 'danger')
                return redirect(url_for('routes.start_a_campaign'))

            # Assign campaign to the logged-in user
            new_campaign = Campaign(
                user_id=session['user_id'],  
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
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('routes.login'))

    # Fetch modules only for the logged-in user

    user = User.query.filter_by(username=session['username']).first()
    modules = TrainingModule.query.filter_by(user_id=session['username']).all()

    return render_template(
        'training_modules.html',
        username=session['username'],
        modules=modules
    )



# Create Training Module 

@routes_bp.route('/create-training-module', methods=['GET', 'POST'])
def create_training_module():
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    form = TrainingModuleForm()
    if form.validate_on_submit():
        new_module = TrainingModule(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            format=form.format.data,
            duration=form.duration.data,
            content=form.content.data
        )
        db.session.add(new_module)
        db.session.commit()
        return redirect(url_for('routes.training_modules'))

    return render_template('create_training_module.html', form=form, username=session['username'])


# Save Training Module (Form POST)

@routes_bp.route('/save-module', methods=['POST'])

def save_module():
    if 'username' not in session:
        return redirect(url_for('routes.login'))
    
    form = TrainingModuleForm()
    if form.validate_on_submit():
        new_module = TrainingModule(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            format=form.format.data,
            duration=form.duration.data,
            content=form.content.data,
            user_id=session['username']   # save who created it
        )
        db.session.add(new_module)
        db.session.commit()
        flash('Module saved successfully!', 'success')
        return redirect(url_for('routes.training_modules'))
    else:
        flash('Error saving module. Please check your inputs.', 'danger')
        return redirect(url_for('routes.create_module'))


#-----buttons in Training Module---------#

#------------------View-------------------#
@routes_bp.route('/training_modules/<int:module_id>')
def view_training_module(module_id):
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    module = TrainingModule.query.get_or_404(module_id)
    return render_template('view_training_module.html', module=module)

#------------------Edit-------------------#
@routes_bp.route('/training_modules/edit/<int:module_id>', methods=['GET', 'POST'])
def edit_training_module(module_id):
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    module = TrainingModule.query.get(module_id)

    if not module:
        flash("Module not found!", "danger")
        return redirect(url_for('routes.training_modules'))

    if request.method == 'POST':
        module.title = request.form['title']
        module.description = request.form['description']
        module.category = request.form['category']
        module.duration = request.form['duration']
        module.format = request.form['format']
        module.content = request.form ['content']

        db.session.commit()

        flash("Training module updated successfully!", "success")
        return redirect(url_for('routes.training_modules'))

    return render_template("edit_training_module.html", module=module)



#------------------Assign-------------------#


@routes_bp.route('/assign_training_module', methods=['GET', 'POST'])
def assign_training_module():
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    # Fetch modules owned by this user
    modules = TrainingModule.query.filter_by(user_id=session['username']).all()

    # Create form and populate choices dynamically
    form = AssignForm()
    form.module_id.choices = [(m.id, m.title) for m in modules]

    if form.validate_on_submit():
        selected_module_id = form.module_id.data
        emails = form.emails.data
        message = form.message.data

        module = TrainingModule.query.get_or_404(selected_module_id)

        # Ensure the logged-in user owns this module
        if module.user_id != session['username']:
            flash("Unauthorized access.", "danger")
            return redirect(url_for('routes.training_modules'))

        # Save assignment to DB
        assignment = Assignment(
            module_id=selected_module_id,
            emails=emails,
            message=message
        )
        db.session.add(assignment)
        db.session.commit()

       
        if emails:
            email_list = [e.strip() for e in emails.split(",") if e.strip()]
            for email in email_list:
                send_assignment_email(email, module, message)

        flash("Training module assigned successfully!", "success")
        return redirect(url_for("routes.training_modules"))

    return render_template("assign_training_module.html", form=form, modules=modules)


#-----------------public facing training content configuration---------------#

from itsdangerous import URLSafeSerializer, BadSignature
from flask import current_app

# Generate a serializer (secret key is from app config)
def get_serializer():
    return URLSafeSerializer(current_app.config['SECRET_KEY'], salt="training-module")

@routes_bp.route('/public_training/<token>')
def public_training_module(token):
    serializer = get_serializer()
    try:
        # Decode the token to get the actual module_id + recipient
        data = serializer.loads(token)  # data is a dict, e.g. {"module_id": 11, "recipient": "someone@example.com"}
        module_id = data.get("module_id")
        recipient = data.get("recipient")
    except BadSignature:
        return "Invalid or expired link.", 403

    module = TrainingModule.query.get_or_404(module_id)


    return render_template('public_training_module.html', module=module, recipient=recipient)




#------------------Delete-------------------#


@routes_bp.route('/delete_training_module/<int:module_id>', methods=['POST'])
def delete_training_module(module_id):
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    module = TrainingModule.query.get_or_404(module_id)

    # Ensure the logged-in user owns this module
    if module.user_id != session['username']:
        flash("You are not authorized to delete this training module.", "danger")
        return redirect(url_for('routes.training_modules'))

    try:
        db.session.delete(module)
        db.session.commit()
        flash("Training module deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while deleting the training module.", "danger")

    return redirect(url_for('routes.training_modules'))



# --- Logout ---
@routes_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('routes.landing'))