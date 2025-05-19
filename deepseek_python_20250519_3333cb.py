from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import re
import random
import string
import threading
import time
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import dns.resolver
import socket
import tldextract
import whois
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Master License Key (generated once)
MASTER_LICENSE_KEY = "OFFICE365-EMAIL-MASTER-7X9R-2P4Q-1K3L"

# Database simulation (in production use a real database)
users = {
    "admin": {
        "password": generate_password_hash("admin123"),
        "license_key": MASTER_LICENSE_KEY,
        "email_quota": float('inf')  # Unlimited for admin
    }
}

email_configs = {}
email_queue = []
active_threads = []
max_threads = 50  # Adjust based on your server capacity

# SMTP Configuration for Office 365
DEFAULT_SMTP_CONFIG = {
    'host': 'smtp.office365.com',
    'port': 587,
    'username': '',
    'password': '',
    'use_tls': True
}

class EmailSender:
    def __init__(self, smtp_config):
        self.smtp_config = smtp_config
    
    def send_email(self, from_email, to_email, subject, body, is_html=False):
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        
        if is_html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))
        
        try:
            with smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port']) as server:
                if self.smtp_config['use_tls']:
                    server.starttls()
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return False

class LinkVerifier:
    @staticmethod
    def verify_link(url):
        try:
            # Basic URL validation
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                return False, "Invalid URL format"
            
            # Check if domain exists
            domain = parsed.netloc
            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                return False, "Domain does not exist"
            
            # Check if URL is reachable
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
                }
                response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                if response.status_code >= 400:
                    return False, f"URL returned status code {response.status_code}"
                
                # Check for phishing indicators
                extracted = tldextract.extract(url)
                domain_name = f"{extracted.domain}.{extracted.suffix}"
                
                # Get WHOIS information
                try:
                    domain_info = whois.whois(domain_name)
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    # Check if domain is newly created (potential phishing)
                    if creation_date and (datetime.now() - creation_date).days < 30:
                        return True, "URL is valid but domain is new (potential risk)"
                except:
                    pass
                
                return True, "URL is valid and reachable"
            except requests.RequestException as e:
                return False, f"URL is not reachable: {str(e)}"
        except Exception as e:
            return False, f"Verification error: {str(e)}"

class LeadExtractor:
    @staticmethod
    def extract_emails_from_text(text):
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text)
    
    @staticmethod
    def extract_links_from_text(text):
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)
    
    @staticmethod
    def extract_from_webpage(url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
            }
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all text
            text = soup.get_text()
            
            # Extract emails
            emails = LeadExtractor.extract_emails_from_text(text)
            
            # Extract links
            links = []
            for link in soup.find_all('a', href=True):
                links.append(link['href'])
            
            return {
                'emails': list(set(emails)),
                'links': list(set(links))
            }
        except Exception as e:
            return {'error': str(e)}

def process_email_queue():
    while True:
        if email_queue and len(active_threads) < max_threads:
            email_data = email_queue.pop(0)
            thread = threading.Thread(target=send_email_thread, args=(email_data,))
            active_threads.append(thread)
            thread.start()
        time.sleep(0.1)

def send_email_thread(email_data):
    try:
        sender = EmailSender(email_data['smtp_config'])
        success = sender.send_email(
            email_data['from_email'],
            email_data['to_email'],
            email_data['subject'],
            email_data['body'],
            email_data.get('is_html', False)
        )
        if not success:
            print(f"Failed to send email to {email_data['to_email']}")
    finally:
        active_threads.remove(threading.current_thread())

# Start email processing thread
email_thread = threading.Thread(target=process_email_queue, daemon=True)
email_thread.start()

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        license_key = request.form.get('license_key', '')
        
        if username in users and check_password_hash(users[username]['password'], password):
            if license_key == users[username]['license_key'] or license_key == MASTER_LICENSE_KEY:
                session['username'] = username
                session['license_key'] = license_key
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid license key', 'danger')
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        license_key = request.form['license_key']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
        elif username in users:
            flash('Username already exists', 'danger')
        elif license_key != MASTER_LICENSE_KEY:
            flash('Invalid master license key', 'danger')
        else:
            users[username] = {
                'password': generate_password_hash(password),
                'license_key': license_key,
                'email_quota': 100000  # 100k daily quota
            }
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_data = users.get(session['username'], {})
    return render_template('dashboard.html', 
                          username=session['username'],
                          email_quota=user_data.get('email_quota', 0))

@app.route('/configure_smtp', methods=['POST'])
def configure_smtp():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    smtp_config = {
        'host': request.form.get('host', DEFAULT_SMTP_CONFIG['host']),
        'port': int(request.form.get('port', DEFAULT_SMTP_CONFIG['port'])),
        'username': request.form['username'],
        'password': request.form['password'],
        'use_tls': request.form.get('use_tls', 'true') == 'true'
    }
    
    email_configs[session['username']] = smtp_config
    return jsonify({'success': True})

@app.route('/send_email', methods=['POST'])
def send_email():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if session['username'] not in email_configs:
        return jsonify({'error': 'SMTP not configured'}), 400
    
    from_email = request.form['from_email']
    to_emails = [email.strip() for email in request.form['to_emails'].split(',')]
    subject = request.form['subject']
    body = request.form['body']
    is_html = request.form.get('is_html', 'false') == 'true'
    
    # Check quota
    user_data = users.get(session['username'], {})
    if len(to_emails) > user_data.get('email_quota', 0):
        return jsonify({'error': 'Exceeds daily email quota'}), 400
    
    # Add emails to queue
    smtp_config = email_configs[session['username']]
    for to_email in to_emails:
        email_data = {
            'smtp_config': smtp_config,
            'from_email': from_email,
            'to_email': to_email,
            'subject': subject,
            'body': body,
            'is_html': is_html
        }
        email_queue.append(email_data)
    
    # Update quota
    users[session['username']]['email_quota'] -= len(to_emails)
    
    return jsonify({
        'success': True,
        'message': f'{len(to_emails)} emails added to queue',
        'remaining_quota': users[session['username']]['email_quota']
    })

@app.route('/verify_link', methods=['POST'])
def verify_link():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    url = request.form['url']
    is_valid, message = LinkVerifier.verify_link(url)
    return jsonify({
        'valid': is_valid,
        'message': message,
        'url': url
    })

@app.route('/extract_leads', methods=['POST'])
def extract_leads():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    source = request.form['source']
    if source.startswith('http'):
        result = LeadExtractor.extract_from_webpage(source)
    else:
        emails = LeadExtractor.extract_emails_from_text(source)
        links = LeadExtractor.extract_links_from_text(source)
        result = {
            'emails': emails,
            'links': links
        }
    
    return jsonify(result)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('license_key', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Create the master license key file
    with open('LICENSE_KEY.txt', 'w') as f:
        f.write(f"MASTER LICENSE KEY: {MASTER_LICENSE_KEY}\n")
        f.write("This key provides unlimited access to all features.\n")
        f.write("Keep this key secure as it provides admin privileges.\n")
    
    app.run(host='0.0.0.0', port=5000, threaded=True)