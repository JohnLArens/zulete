# Zulete v2

Zulete is a personal spam firewall for Gmail and iCloud Mail.

## This version includes

- Gmail OAuth connection flow using the Gmail API
- iCloud Mail connection using secure IMAP and an Apple app-specific password
- encryption of stored Gmail OAuth credentials and iCloud app password
- automatic inbox scanning on a configurable interval
- manual "Scan now" controls
- sender and domain allow/block rules
- automatic deletion of mail from explicitly blocked senders
- optional automatic deletion of blocked domains
- optional permanent deletion (Trash is safer and remains the default)
- review quarantine for uncertain mail
- spam folder/label for higher-confidence spam
- activity dashboard and adjustable thresholds

## 1. Install

Python 3.11+ recommended.

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

## 2. Generate Zulete security secrets

Generate a Fernet key:

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Set it as `ZULETE_MASTER_KEY`. Also create a long random `ZULETE_SECRET`.

Example:

    export ZULETE_MASTER_KEY='YOUR_GENERATED_FERNET_KEY'
    export ZULETE_SECRET='YOUR_LONG_RANDOM_SECRET'

## 3. Configure Gmail OAuth

In Google Cloud:

1. Create/select a Google Cloud project.
2. Enable the Gmail API.
3. Configure the Google Auth consent screen.
4. Create an OAuth 2.0 client for a Web application.
5. Add this authorized redirect URI:

       http://127.0.0.1:5055/oauth2callback

6. Set:

       export GOOGLE_CLIENT_ID='...apps.googleusercontent.com'
       export GOOGLE_CLIENT_SECRET='...'
       export GOOGLE_REDIRECT_URI='http://127.0.0.1:5055/oauth2callback'

Zulete requests Gmail `gmail.modify` access so it can read messages, add/remove labels,
move messages to Trash, and organize filtered mail.

## 4. Configure iCloud

In your Apple Account, create an app-specific password if required for third-party mail
access. Then use Zulete's "Email Accounts" page to enter the iCloud email address and
that app-specific password. The password is encrypted before being stored locally.

## 5. Run

    python app.py

Open:

    http://127.0.0.1:5055

## Deletion design

Zulete deliberately separates *suspected spam* from *known blocked senders*.

- uncertain spam -> Zulete Review
- high-scoring spam -> Zulete Spam
- explicitly blocked sender + Auto-Delete ON -> Trash
- explicitly blocked sender + Permanent Delete ON -> irreversible Gmail delete / IMAP delete

This reduces the risk of a classifier permanently deleting legitimate mail.

## Hosting

The app is ready to be adapted for a private hosted server, but production deployment
still needs a domain/hosting environment and production Google OAuth credentials.
For a public multi-user product, add user accounts, CSRF protection, a production WSGI
server, HTTPS, database migrations, per-user encryption keys, audit logging, and provider
verification/compliance as applicable.
