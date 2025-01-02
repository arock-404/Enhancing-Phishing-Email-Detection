# email_scanner/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('scan_emails/', views.scan_emails, name='scan_emails'),
    path('results/', views.email_scan_results, name='email_scan_results'),
    path('email/<int:email_id>/', views.email_detail, name='email_detail'),
]
