import os
import imaplib
import email
from email.header import decode_header
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from .models import EmailScanResult, AttachmentScanResult, LinkScanResult
from .utils import analyze_email_headers, scan_file_with_clamav, extract_links, check_url_virustotal
import joblib  # Make sure to import joblib at the top
from bs4 import BeautifulSoup

# Email account credentials

username = "forcspproject@gmail.com"
password = "ltlmeynncjldogwh"



def scan_emails(request):
    # Load the machine learning model and vectorizer
    try:
        model_path = 'E:\\CSP_Project\\phishing_email_detection\\models\\random_forest_classifier.joblib'
        model = joblib.load(model_path)
        
        vectorizer_path = 'E:\\CSP_Project\\phishing_email_detection\\models\\tfidf_vectorizer.joblib'
        vectorizer = joblib.load(vectorizer_path)
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        model = None
        vectorizer = None
    except Exception as e:
        print(f"Error loading model/vectorizer: {e}")
        model = None
        vectorizer = None

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
    
    if email_ids:
        # Fetch the latest email
        latest_email_id = email_ids[-1]
        
        # Fetch the email by ID
        status, msg_data = mail.fetch(latest_email_id, "(RFC822)")

        # Parse the email content
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                # Decode the email subject
                subject = decode_header(msg["Subject"])[0][0]
                if isinstance(subject, bytes):
                    subject = subject.decode()
                from_ = msg.get("From")

                # Analyze email headers
                header_analysis_results = analyze_email_headers(msg)

                # Initialize lists for storing the attachments and links
                attachment_scan_results = []
                links_scan_results = []
                body = ""

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
                                attachment_scan_results.append({
                                    'file': filename,
                                    'status': scan_result['status'],
                                    'details': scan_result['details']
                                })

                        # Get email body
                        if content_type == "text/plain" or content_type == "text/html":
                            try:
                                body = part.get_payload(decode=True).decode()
                                links = extract_links(body)
                                if links:
                                    links_scan_results = check_url_virustotal(links)
                            except Exception as e:
                                print(f"Error decoding body: {e}")
                else:
                    content_type = msg.get_content_type()
                    if content_type == "text/plain" or content_type == "text/html":
                        body = msg.get_payload(decode=True).decode()
                        links = extract_links(body)
                        if links:
                            links_scan_results = check_url_virustotal(links)

                # Perform ML analysis on the email body
                if model is not None and vectorizer is not None:
                    # Strip HTML tags using BeautifulSoup
                    body_text = BeautifulSoup(body, "html.parser").get_text()
                    email_tfidf = vectorizer.transform([body_text])  # Using body
                    prediction = model.predict(email_tfidf)

                    # Determine the status based on the prediction
                    ml_analysis_result = "Phishing" if prediction[0] == 1 else "Safe"
                else:
                    ml_analysis_result = "Model or vectorizer not loaded"

                # Store the results in the database
                email_result = EmailScanResult.objects.create(
                    subject=subject,
                    from_email=from_,
                    body=body,
                    header_analysis="\n".join(header_analysis_results),
                    scan_date=datetime.now(),
                    ml_analysis=ml_analysis_result  # Save ML result
                )

                # Save attachments to the database
                for attachment in attachment_scan_results:
                    AttachmentScanResult.objects.create(
                        email=email_result,
                        file=attachment['file'],
                        status=attachment['status'],
                        details=attachment['details']
                    )

                # Save links to the database
                for link in links_scan_results:
                    LinkScanResult.objects.create(
                        email=email_result,
                        url=link['url'],
                        status=link['status'],
                        details=link['details']
                    )

    else:
        print("No emails found.")

    # Close the connection and logout
    mail.close()
    mail.logout()

    # Redirect to the email scan results page
    return redirect('email_scan_results')



def email_scan_results(request):
    # Retrieve and render scan results
    results = EmailScanResult.objects.all().order_by('-scan_date')
    return render(request, 'email_scanner/email.html', {'email_scan_results': results})

def email_detail(request, email_id):
    email = get_object_or_404(EmailScanResult, id=email_id)
    attachments = email.attachment_scan_results.all()
    links = email.links_scan_results.all()
    
    return render(request, 'email_scanner/email_detail.html', {
        'email': email,
        'attachments': attachments,
        'links': links
    })