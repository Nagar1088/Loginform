import re
import random
import time
from django.contrib.auth import get_user_model
from django.core.checks import register
from django.core.mail import send_mail
from django.conf import settings

User = get_user_model()
OTP_VALID_SECONDS = 300

def validate_name(name, field_name, max_length=None):
    if not name:
        return f'Please enter {field_name}'
    if not re.match(r'^[a-zA-Z]+$', name):
        return f'Invalid {field_name} (only letters allowed)'
    if max_length and len(name) > max_length:
        return f'{field_name.capitalize()} must be less than {max_length} characters'
    return None

def validate_email(email, check_exists=False):
    if not email:
        return 'Please enter email'
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return 'Please enter a valid email address'
    if check_exists and User.objects.filter(email=email).exists():
        return 'Email already exists'
    return None

def validate_phone(phone, check_exists=False):
    if not phone:
        return 'Please enter phone number'
    if not re.match(r'^[6-9]\d{9}$', phone):
        return 'Invalid phone number'
    if check_exists and User.objects.filter(phone=phone).exists():
        return 'Phone already exists'
    return None

def validate_password(password, confirm_password=None):
    if not password:
        return 'Please enter password'
    if len(password) < 8:
        return 'Password must be at least 8 characters'
    if not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter'
    if not re.search(r'[a-z]', password):
        return 'Password must contain at least one lowercase letter'
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return 'Password must contain at least one special character'
    if confirm_password is not None and password != confirm_password:
        return 'Passwords do not match'
    return None

def generate_username(email):
    username = email.split('@')[0][:30]
    while User.objects.filter(username=username).exists():
        username = f"{username}{random.randint(1, 999)}"
    return username


def generate_username(email):
    username = email.split('@')[0][:30]
    while User.objects.filter(username=username).exists():
        username = f"{username}{random.randint(1, 999)}"
    return username

def send_otp_email(request, email):
    otp = str(random.randint(100000, 999999))

    request.session['otp'] = otp
    request.session['otp_email'] = email
    request.session['otp_created_at'] = time.time()

    try:
        send_mail(
            subject='Password Reset OTP',
            message=f'Your OTP is: {otp}\nIt is valid for 5 minutes.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        return True, None
    except Exception as e:
        return False, str(e)

# def verify_otp(request, otp_input):
#     stored_otp = request.session.get('otp')
#     otp_created_at = float(request.session.get('otp_created_at', 0))

#     if (time.time() - otp_created_at) > OTP_VALID_SECONDS:
#         return False, 'OTP has expired. Please request a new one.'
#     if not stored_otp or otp_input != stored_otp:
#         return False, 'Invalid OTP.'
#     return True, None

OTP_VALID_SECONDS = 300  # 5 minutes

def verify_otp(request, otp_input):
    stored_otp = request.session.get('otp')
    otp_created_at = float(request.session.get('otp_created_at', 0))

    if not stored_otp:
        return False, 'No OTP found. Please request a new OTP.', True

    if (time.time() - otp_created_at) > OTP_VALID_SECONDS:
        # Expired OTP ko remove kar do
        request.session.pop('otp', None)
        request.session.pop('otp_created_at', None)

        return False, 'OTP has expired. Please request a new OTP.', True

    if otp_input != stored_otp:
        return False, 'Invalid OTP.', False

    return True, None, False

