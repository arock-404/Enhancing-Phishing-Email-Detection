# Phishing Email Detection System 
This project aims to build a comprehensive phishing email detection system using machine learning, natural language processing (NLP), and malware scanning tools. The system is integrated into a Django-based web application, designed to resemble an email client interface, and helps users detect phishing emails by analyzing their content, links, and attachments.

## Features
- Email Content Analysis: Uses a machine learning model to classify emails as phishing or safe based on their textual content.
- Attachment Scanning: Integrates ClamAV (via Docker) to scan attachments for malware.
- Link Analysis: Leverages the VirusTotal API to detect malicious URLs in email content.
- Dataset Matching: Matches emails against a public phishing email dataset for additional verification.
- Interactive Interface: A user-friendly web interface inspired by Gmail for seamless interaction.
- User Alerts: Notifies users with warnings if an email is flagged as suspicious.

## Installation

### Prerequisites
- Python 3.8+
- Docker
- Django
- ClamAV Docker image
- VirusTotal API key

### Steps
- Clone the repository:
  `git clone https://github.com/arock-404/Enhancing-Phishing-Email-Detection.git`
- Install dependencies:
 `pip install -r requirements.txt`
- Configure the settings:
  - Update the `settings.py` file with your database configurations.
  - Add your VirusTotal API key in the designated section of the settings.
- Download and set up the machine learning models:
  - Place the `random_forest_classifier.joblib` and `tfidf_vectorizer.joblib` files in the models directory
 
- Run the ClamAV Docker container:
  ```docker run --name clamav -d clamav/clamav```

- Start the development server:
  ` python manage.py runserver`
- Access the application at http://127.0.0.1:8000.
