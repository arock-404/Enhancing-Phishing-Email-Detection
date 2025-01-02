# email_scanner/models.py
from django.db import models

class EmailScanResult(models.Model):
    subject = models.CharField(max_length=255)
    from_email = models.EmailField()
    body = models.TextField(default="No body")  # Default value added here
    header_analysis = models.TextField()
    ml_analysis = models.CharField(max_length=50, null=True)  # Add for ML analysis
    status = models.CharField(max_length=20, null=True)  # Add to indicate phishing status
    scan_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.subject
    
class AttachmentScanResult(models.Model):
    email = models.ForeignKey(EmailScanResult, related_name='attachment_scan_results', on_delete=models.CASCADE)
    file = models.CharField(max_length=255)  # Store the file name
    status = models.CharField(max_length=50)  # Status of the scan (e.g., 'Safe', 'Malicious')
    details = models.TextField()  # Additional details about the scan

    def __str__(self):
        return self.file
class LinkScanResult(models.Model):
    email = models.ForeignKey(EmailScanResult, related_name='links_scan_results', on_delete=models.CASCADE)
    url = models.URLField()  # Store the link
    status = models.CharField(max_length=50)  # Status of the scan (e.g., 'Safe', 'Malicious')
    details = models.TextField()  # Additional details about the scan

    def __str__(self):
        return self.url

