from django.core.mail import send_mail
from django.conf import settings
import random
import string

def send_otp(email, otp):
    subject = 'Your OTP Code'
    message = f'Your OTP code is {otp}.'
    send_mail(
        subject, 
        message, 
        settings.DEFAULT_FROM_EMAIL, 
        [email], 
        fail_silently=False,
    )






def send_verification_email(email, token, reset=False):
    subject = 'Verify Your Email' if not reset else 'Reset Your Password'
    message = f'Click the link to verify your email: {settings.FRONTEND_URL}/verify-email/{token}' \
              if not reset else \
              f'Click the link to reset your password: {settings.FRONTEND_URL}/reset-password/{token}'
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

def generate_verification_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=20))


from django.contrib.auth.tokens import PasswordResetTokenGenerator  
import six

class TokenGenerator(PasswordResetTokenGenerator):  
    def _make_hash_value(self, user, timestamp):  
        return (  
            six.text_type(user.pk) + six.text_type(timestamp) +  
            six.text_type(user.is_active)  
        )  
account_activation_token = TokenGenerator()  