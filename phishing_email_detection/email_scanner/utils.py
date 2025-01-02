import imaplib
import email
from email.header import decode_header
import re
import os
import sys
import clamd
import base64
import requests
import json  
import joblib

# Add the project directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import django

# Set the default settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'email_scanner.settings')

# Initialize Django
django.setup()

from django.conf import settings


# Email account credentials
username = "forcspproject@gmail.com"
password = "ltlmeynncjldogwh"

# VirusTotal API key
VT_API_KEY = "e9a106daa260216888507bd3224332b091e51b8d2358b7b81701fdaf6ee12e52"

# ClamAV Docker container details
container_host = "127.0.0.1"
container_port = 3310

# Function to scan file with ClamAV running in Docker container
def scan_file_with_clamav(file_path):
    try:
        cd = clamd.ClamdNetworkSocket(container_host, container_port)
        scan_result = cd.scan(file_path)

        if not scan_result:
            return {"file": file_path, "status": "clean", "details": "No infection found."}

        file_status = scan_result[file_path][0]
        if file_status == "OK":
            return {"file": file_path, "status": "clean", "details": "No infection found."}
        elif file_status == "FOUND":
            return {"file": file_path, "status": "infected", "details": scan_result[file_path][1]}
        else:
            return {"file": file_path, "status": "error", "details": f"Unexpected result: {scan_result}"}

    except Exception as e:
        return {"file": file_path, "status": "error", "details": str(e)}

# Function to check URLs with VirusTotal
def check_url_virustotal(links):
    results = []
    for url in links:
        # Encode the URL to get the URL ID
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

        # Check the response status
        if response.status_code == 200:
            json_response = response.json()
            if 'data' in json_response and 'attributes' in json_response['data']:
                scan_data = json_response['data']['attributes']['last_analysis_stats']
                malicious = scan_data.get('malicious', 0)
                harmless = scan_data.get('harmless', 0)
                suspicious = scan_data.get('suspicious', 0)

                # Determine the status based on the scan results
                if malicious > 0:
                    status = 'Malicious'
                    details = f"Warning: <strong>URL {url}</strong> is flagged as malicious by <strong>{malicious}/94</strong> security vendors on VirusTotal."
                elif suspicious > 0:
                    status = 'Suspicious'
                    details = f"Warning: <strong>URL {url}</strong> is flagged as suspicious by <strong>{suspicious}/94</strong> security vendors on VirusTotal."
                else:
                    status = 'Safe'
                    details = f"<strong>URL {url}</strong> is considered safe by <strong>{harmless}/94</strong> security vendors on VirusTotal."

                # Append structured result
                results.append({
                    'url': url,
                    'status': status,
                    'details': details
                })
            else:
                results.append({
                    'url': url,
                    'status': 'Unknown',
                    'details': f"Warning: <strong>URL {url}</strong> might be suspicious (no detailed scan results available)."
                })
        else:
            results.append({
                'url': url,
                'status': 'Error',
                'details': f"Error: Failed to retrieve information from VirusTotal for <strong>{url}</strong> (status code {response.status_code})."
            })

    return results



# Function to extract links from email body
def extract_links(body):
    urls = re.findall(r'https?://[^\s"\'>]+', body)
    return urls

# Function to analyze email headers
def analyze_email_headers(headers):
    analysis_results = []
    
    # Extract key headers
    from_header = headers.get('From', '')
    received_headers = headers.get_all('Received', [])
    return_path = headers.get('Return-Path', '')
    reply_to = headers.get('Reply-To', '')
    
    # Basic analysis
    analysis_results.append(f"From: {from_header}")
    analysis_results.append(f"Return-Path: {return_path}")
    analysis_results.append(f"Reply-To: {reply_to}")
    
    # Analyzing Received headers to trace the email path
    if received_headers:
        analysis_results.append("Received Headers Trace:")
        for idx, received in enumerate(received_headers):
            analysis_results.append(f"Received-{idx + 1}: {received}")
    
    return analysis_results

# Connect to the Gmail IMAP server
mail = imaplib.IMAP4_SSL("imap.gmail.com")

# Login to your account
mail.login(username, password)

# Select the mailbox (e.g., "inbox")
mail.select("inbox")

# Search for all emails
status, messages = mail.search(None, "ALL")

# Convert messages to a list of email IDs
email_ids = messages[0].split()

# Fetch the latest email
latest_email_id = email_ids[-1]

# Fetch the email by ID
status, msg_data = mail.fetch(latest_email_id, "(RFC822)")

# Define the absolute paths to the model and vectorizer using the BASE_DIR from settings
model_path = model_path = os.path.join(settings.BASE_DIR, 'models', 'random_forest_classifier.joblib')
vectorizer_path = os.path.join(settings.BASE_DIR, 'models', 'tfidf_vectorizer.joblib')

# Load the pre-trained Random Forest model and the TF-IDF vectorizer
model = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

# Define a function to predict using the ML model
def analyze_with_ml_model(email_body):
    # Vectorize the email body using the loaded TF-IDF vectorizer
    body_vector = vectorizer.transform([email_body])  # Transform the body into a vector

    # Use the model to predict whether the email is phishing or safe
    prediction = model.predict(body_vector)
    return "Phishing" if prediction == 1 else "Safe"

for response_part in msg_data:
    if isinstance(response_part, tuple):
        msg = email.message_from_bytes(response_part[1])

        # Decode the email subject
        subject = decode_header(msg["Subject"])[0][0]
        if isinstance(subject, bytes):
            subject = subject.decode()
        from_ = msg.get("From")

        # Initialize lists for attachments, links, and header analysis
        attachment_scan_results = []
        links_scan_results = []
        header_analysis_results = []
        body_content = ""  # Initialize to store email body

        # Analyze email headers
        header_analysis_results = analyze_email_headers(msg)

        # Process email parts
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Check for attachments
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        filepath = os.path.join("attachments", filename)
                        if not os.path.isdir("attachments"):
                            os.mkdir("attachments")
                        with open(filepath, "wb") as f:
                            f.write(part.get_payload(decode=True))
                        
                        # Scan the saved attachment with ClamAV
                        scan_result = scan_file_with_clamav(filepath)
                        attachment_scan_results.append(scan_result)

                # Get email body
                if content_type == "text/plain" or content_type == "text/html":
                    try:
                        body = part.get_payload(decode=True).decode()
                        body_content += body  # Append body content
                        links = extract_links(body)
                        if links:
                            links_scan_results = check_url_virustotal(links)
                    except:
                        pass
        else:
            content_type = msg.get_content_type()
            if content_type == "text/plain" or content_type == "text/html":
                body = msg.get_payload(decode=True).decode()
                body_content = body  # Assign body content
                links = extract_links(body)
                if links:
                    links_scan_results = check_url_virustotal(links)

        # Use the ML model to predict phishing or safe
        ml_analysis_result = analyze_with_ml_model(body_content)

        # Create a dictionary to hold the email analysis results
        email_analysis = {
            "subject": subject,
            "from": from_,
            "body": body_content,  # Add body to the dictionary
            "header_analysis": header_analysis_results,
            "attachment_scan_results": attachment_scan_results,
            "links_scan_results": links_scan_results,
            "ml_analysis": ml_analysis_result  # Add ML result to the dictionary
        }

        # Print the JSON formatted results
        print(json.dumps(email_analysis, indent=4))

# Close the connection and logout
mail.close()
mail.logout()

