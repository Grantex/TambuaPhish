# TambuaPhish

> **TambuaPhish** — an email phishing simulator & security awareness training tool.
> Designed to simulate realistic phishing campaigns, measure human susceptibility, and deliver targeted training to proactively reduce risk.

> **Safety note:** Links generated and used by TambuaPhish are **non-malicious** and contain **no payloads**. They are safe, educational tracking links used only to record click events for awareness training.

---

## Project overview

TambuaPhish is a pragmatic tool that blends software engineering and cybersecurity: craft phishing-style emails, launch simulated campaigns, track who clicked and when, and deliver targeted follow-up training modules. The emphasis is on practical awareness — **education, not exploitation**.

---

## Problem & Objectives

**Problem**

* Human error is the most exploited attack vector; phishing remains highly effective.
* Many organizations have strong technical defenses but lack hands-on, targeted user training making human resources the weakest link in most organizations.
* Over 90% of successful breaches involve users interacting with phishing content or revealing credentials via social engineering.

**Objectives**

1. Simulate realistic phishing campaigns.
2. Track and analyze user responses (clicks, timestamps, CTR).
3. Deliver targeted awareness training to reduce future risk.

---

## Key features

* **Dashboard** — at-a-glance campaign metrics (total campaigns, recipients, clicks, CTR).
* **Templates** — create, edit, and delete phishing email templates using a rich text editor(Quill).
* **Campaigns** — select a template, add recipients, launch simulations, and close campaigns.
* **Click Tracking** — log recipient clicks and timestamps (for analytics, follow-up training).
* **Training Modules** — create and assign awareness content to users who interacted with simulations.
* **Reporting & Analytics** — visualized with Chart.js to dynamically surface campaign performance.
* **Email Delivery** — via Flask-Mail (SMTP).
* **Secure auth** — passwords hashed with Werkzug PBKDF2-HMAC-SHA256 (via `generate_password_hash` / `check_password_hash`).
* **Reporting** - generate reports of phishing campaigns which can be used to communicate to stakeholders such as CEOs. 

---

## Technical stack

* **Frontend:** HTML, CSS, JavaScript, Bootstrap, Quill.js (email editor), Chart.js (analytics)
* **Backend:** Python, Flask (blueprints, Jinja2 templates)
* **Database:** SQLite (prototype) — architecture supports easy migration to PostgreSQL/MySQL
* **Mailing:** Flask-Mail (SMTP)
* **Auth / Encryption:** Werkzeug security (PBKDF2-SHA256)
* **Project layout:** modular (`config.py`, `models.py`, `forms.py`, `routes/blueprints`)

---

## Architecture & structure

Typical project structure:

```
TambuaPhish/
├─ run.py                 # app entry (create_app)
├─ config.py              # centralized config (env-driven)
├─ requirements.txt
├─ README.md
└─ tambuaphish/           # application package
├__init__.py         # app factory, db init
├─ models.py           # SQLAlchemy models (User, Template, Campaign, Recipient)
├─ forms.py            # Flask-WTF forms
├─ routes.py           # or routes/ blueprint modules
├─ templates/          # Jinja2 HTML templates
└─ static/             # CSS, JS (Quill, Chart.js glue)
```

Key components:

* `config.py` — load config from environment (`.env` support recommended).
* `models.py` — `User`, `CustomEmailTemplate`, `Campaign`, `TrainingModules`,`Recipient` (SQLAlchemy).
* `forms.py` — Flask-WTF forms with CSRF protection.
* `routes.py` — blueprint-based route handlers for auth, templates, campaigns, analytics.
* `templates/` & `static/` — UI views and assets.

---

## Quickstart (Run locally)

**Prerequisites:** Python 3.9+, git, a terminal.

1. Clone the repo:

```bash
git clone <repo-url>
cd TambuaPhish
```

2. Create & activate a virtual environment:

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create a `.env` file (project root) with at least:

```env
SECRET_KEY=replace-with-strong-secret
DATABASE_URL=sqlite:///tambuaphish.db 
MAIL_SERVER=use-your-mail-server (eg. gmail)
MAIL_PORT=mail-port
MAIL_USE_SSL=True
MAIL_USERNAME=email-from-which-TambuaPhis-launches-email-from
MAIL_PASSWORD=replace-with-smtp-password
```

5. Initialize the database (example using app factory pattern):

```python
# quick db bootstrap
from tambuaphish import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
```
(this will create a new db)

6. Run the app:

```terminal
python run.py
# or
flask run
```

7. Open `http://127.0.0.1:5000` in your browser.

---

## Usage / Typical flow

1. **Sign up / log in** .
2. **Create** a template (Quill-powered WYSIWYG editor).
3. **Start a campaign**: pick template, add recipients, launch.
4. **Recipients click** the tracking link — the system logs the click timestamp & recipient id.
5. **Review analytics** on dashboard and campaign pages.
6. **Assign training** to recipients who clicked to reinforce learning. (you have to create the training materials yourself and put links to the training materials in TambuaPhish)

---

## Security considerations

* **Non-malicious links:** Links used for tracking are inert—they do not contain payloads or execute code. They exist solely to record click events for educational metrics and training triggers.
* **Password security:** Passwords are stored using a salted, iterative PBKDF2-HMAC-SHA256 hash (Werkzeug). Use strong passwords and consider Argon2 for production.
* **CSRF:** All state-changing forms use Flask-WTF CSRF protection via `form.hidden_tag()`.
* **Secrets:** Use environment variables or a secrets manager in production. Avoid committing credentials.
* **Production hardening:** Use HTTPS, secure cookies, CSP, rate limiting, logging, and a robust DB like PostgreSQL.

---

## Testing & validation

* **Manual tests:** create templates, launch campaigns, click the link as a test recipient, verify click logging & analytics.
* **Form validation:** WTForms & server-side validation checks.
* **Unit tests (recommended):** model constraints, route permission checks, form validation.
* **Load testing:** simulate bulk recipient lists and email send throttling for real-world readiness.

---

## Challenges & future work

* **Prototype DB:** currently SQLite — migrate to PostgreSQL for production.
* **Error handling:** enhance user-facing error messages & server-side validation.
* **Content:** provide pre-built template library and curated training modules.
* **Deployment:** containerize (Docker), configure CI/CD, and use a cloud provider with secure SMTP relays and monitoring.
* **Security improvements:** Argon2 for password hashing, RBAC, audit logging, and centralized secrets.

---

## Achievements & takeaways

* Built a working MVP covering creation → launch → tracking → training.
* Implemented secure auth, email delivery integration, and analytics dashboards.
* Modular code structure (config, models, forms, routes) ready for iterative extension and hardening.

---

## How this showcases my skills

* **Full-stack development:** frontend (Quill, Chart.js) and backend (Flask, SQLAlchemy).
* **Security engineering:** secure password storage, CSRF, and safe simulation design.
* **Data & analytics:** transformed click events into actionable campaign metrics.
* **Project management:** scoped an MVP, prioritized features, and documented tradeoffs.
* **DevOps awareness:** environment-driven config, simple runbook for reviewers.

---

## Contact 

* **Author:** Grant Ombongi Nyamweya
* **Contacts** grantthesoftwareengineer@gmail.com | https://github.com/Grantex | https://www.linkedin.com/in/grant-ombongi-21912b273/ 

## 🧾 License
This project is licensed under the [MIT License](./LICENSE).  
© 2025 Grant Ombongi Nyamweya


---

