import pytest
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from django.utils import timezone
import random
import string
import uuid
from django.core import mail
from django.conf import settings
from Verify.models import EmailVerification


User = get_user_model()

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def create_user():
    def _create_user(email, password, username='userx', is_active=False):
        otp = ''.join(random.choices(string.digits, k=6))
        otp_expiry = timezone.now() + timezone.timedelta(minutes=60)

        user = User(
            email=email,
            username=username,
            otp=otp,
            otp_expiry=otp_expiry,
            max_otp_try=5,
            is_active=is_active
        )
        user.set_password(password)
        user.save()
        return user, otp
    return _create_user

# Test User Registration
@pytest.mark.django_db
def test_user_registration(api_client, create_user):
    user_data = {
        'username': 'userx',
        'email': 'userx@gmail.com',
        'password1': 'password123',
        'password2': 'password123'
    }

    response = api_client.post('/api/register/', user_data, format='json')
    
    assert response.status_code == status.HTTP_201_CREATED
    assert 'message' in response.data
    assert len(mail.outbox) == 1
    assert 'Your OTP code is' in mail.outbox[0].body

# Test OTP Verification
@pytest.mark.django_db
def test_verify_otp(api_client, create_user):
    user, otp = create_user('userx@gmail.com', 'password123')
    EmailVerification.objects.create(
        user=user,
        verification_code=otp,
        is_verified=False,
        created_at=timezone.now()
    )

    otp_data = {
        'email': 'userx@gmail.com',
        'otp': otp
    }

    response = api_client.post('/api/verify-otp/', otp_data, format='json')
    
    assert response.status_code == status.HTTP_200_OK
    assert 'message' in response.data
    user.refresh_from_db()
    assert user.is_active

# Test Regenerate OTP
@pytest.mark.django_db
def test_regenerate_otp(api_client, create_user):
    user, _ = create_user('userx@gmail.com', 'password123')
    user.max_otp_try = 1
    user.save()

    response = api_client.post(f'/api/regenerate-otp/{user.id}/', format='json')

    assert response.status_code == status.HTTP_200_OK
    assert 'message' in response.data
    assert len(mail.outbox) == 2
    assert 'Your new OTP code is' in mail.outbox[1].body
 
# Test Login
@pytest.mark.django_db
def test_login(api_client, create_user):
    user, _ = create_user('userx@gmail.com', 'password123', is_active=True)
    EmailVerification.objects.create(
        user=user,
        verification_code=user.otp,
        is_verified=True,
        created_at=timezone.now()
    )

    login_data = {
        'email': 'userx@gmail.com',
        'password': 'password123'
    }

    response = api_client.post('/api/token/', login_data, format='json')
    
    assert response.status_code == status.HTTP_200_OK
    assert 'access' in response.data
    assert 'refresh' in response.data


# Test Logout
@pytest.mark.django_db
def test_logout(api_client, create_user):
    user, _ = create_user('userx@gmail.com', 'password123', is_active=True)
    EmailVerification.objects.create(
        user=user,
        verification_code=user.otp,
        is_verified=True,
        created_at=timezone.now()
    )

    login_data = {
        'email': 'userx@gmail.com',
        'password': 'password123'
    }

    response = api_client.post('/api/token/', login_data, format='json')
    assert response.status_code == status.HTTP_200_OK
    refresh_token = response.data.get('refresh')
    assert refresh_token, "Refresh token should be present in response"

    logout_data = {
        'refresh': refresh_token
    }

    response = api_client.post('/api/logout/', logout_data, format='json')
    
    assert response.status_code == status.HTTP_205_RESET_CONTENT
    assert 'detail' in response.data

# Test Password Reset Request
@pytest.mark.django_db
def test_password_reset_request(api_client, create_user):
    user, _ = create_user('userx@gmail.com', 'password123')

    data = {
        'email': 'userx@gmail.com'
    }

    response = api_client.post('/api/password-reset/', data, format='json')
    
    assert response.status_code == status.HTTP_200_OK
    assert 'detail' in response.data
    assert len(mail.outbox) == 1
    assert 'Use this link to reset your password' in mail.outbox[0].body

# Test Password Reset Confirm
@pytest.mark.django_db
def test_password_reset_confirm(api_client, create_user):
    user, _ = create_user('userx@gmail.com', 'password123')
    token = uuid.uuid4()
    user.reset_password_token = token
    user.reset_password_token_expiry = timezone.now() + timezone.timedelta(hours=1)
    user.save()

    data = {
        'token': token,
        'new_password': 'newpassword123',
        'confirm_password': 'newpassword123'
    }

    response = api_client.post('/api/password-reset-confirm/', data, format='json')
    
    assert response.status_code == status.HTTP_200_OK
    assert 'detail' in response.data
    user.refresh_from_db()
    assert user.check_password('newpassword123')

# Test User CSV Export
@pytest.mark.django_db
def test_user_csv_export(api_client, create_user):
    create_user('userx@gmail.com', 'password123')

    response = api_client.get('/api/export-users/', format='json')
    
    assert response.status_code == status.HTTP_200_OK
    assert 'message' in response.data
    assert "CSV file 'usersname.csv' has been created successfully." in response.data['message']

# Test Email Verification
@pytest.mark.django_db
def test_email_verification(api_client, create_user):
    user, otp = create_user('userx@gmail.com', 'password123')
    EmailVerification.objects.create(
        user=user,
        verification_code=otp,
        is_verified=False,
        created_at=timezone.now()
    )

    verification_data = {
        'verification_code': otp
    }

    response = api_client.post('/api/email-verification/', verification_data, format='json')
    
    assert response.status_code == status.HTTP_200_OK
    assert 'detail' in response.data
    user.refresh_from_db()
    assert user.is_active
