import uuid
import pytest
from rest_framework.exceptions import ValidationError
from rest_framework import status
from django.utils import timezone
from datetime import timedelta
from Verify.models import UserModel, EmailVerification
from Verify.serializers import (
    UserSerializer,
    UserRegistrationSerializer,
    VerifyOTPSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer
)
from django.contrib.auth import get_user_model

User = get_user_model()

@pytest.mark.django_db
def test_user_serializer():
    user = UserModel.objects.create_user(
        email="userx@gmail.com",
        password="password123"
    )
    serializer = UserSerializer(user)
    data = serializer.data
    assert data['email'] == "userx@gmail.com"
    assert 'phone_number' in data
    assert 'username' in data
    assert 'is_active' in data


@pytest.mark.django_db
def test_user_registration_serializer_valid():
    data = {
        'email': 'userx@gmail.com',
        'username': 'newuserx',
        'password1': 'password123',
        'password2': 'password123'
    }
    serializer = UserRegistrationSerializer(data=data)
    assert serializer.is_valid()

    user, otp = serializer.save()
    assert UserModel.objects.filter(email='userx@gmail.com').exists()
    assert user.otp == otp
    assert user.otp_expiry > timezone.now()


@pytest.mark.django_db
def test_user_registration_serializer_invalid_passwords():
    data = {
        'email': 'userx@gmail.com',
        'username': 'newuser',
        'password1': 'newpassword123',
        'password2': 'differentpassword'
    }
    serializer = UserRegistrationSerializer(data=data)
    assert not serializer.is_valid()
    assert 'Passwords must match.' in serializer.errors['non_field_errors']


@pytest.mark.django_db
def test_verify_otp_serializer_valid():
    data = {
        'email': 'userx@gmail.com',
        'otp': '123456'
    }
    serializer = VerifyOTPSerializer(data=data)
    assert serializer.is_valid()


@pytest.mark.django_db
def test_password_reset_request_serializer_valid():
    UserModel.objects.create_user(
        email='userx@gmail.com',
        password='securepassword'
    )
    data = {'email': 'userx@gmail.com'}
    serializer = PasswordResetRequestSerializer(data=data)
    assert serializer.is_valid()


@pytest.mark.django_db
def test_password_reset_request_serializer_invalid_email():
    data = {'email': 'nonexistent@example.com'}
    serializer = PasswordResetRequestSerializer(data=data)
    assert not serializer.is_valid()
    assert 'No user with this email address.' in serializer.errors['email']

@pytest.mark.django_db
def test_password_reset_confirm_serializer_valid():
    valid_uuid = str(uuid.uuid4())  # Generate a valid UUID
    data = {
        'token': valid_uuid,
        'new_password': 'newpassword123',
        'confirm_password': 'newpassword123'
    }
    serializer = PasswordResetConfirmSerializer(data=data)
    assert serializer.is_valid(), f"Errors: {serializer.errors}"

@pytest.mark.django_db
def test_password_reset_confirm_serializer_invalid_passwords():
    valid_uuid = str(uuid.uuid4())  # Generate a valid UUID
    data = {
        'token': valid_uuid,
        'new_password': 'newpassword123',
        'confirm_password': 'differentpassword'
    }
    serializer = PasswordResetConfirmSerializer(data=data)
    assert not serializer.is_valid()
    assert 'non_field_errors' in serializer.errors
    assert 'Passwords do not match.' in serializer.errors['non_field_errors']

@pytest.mark.django_db
def test_email_verification_serializer():
    email_verification = EmailVerification.objects.create(
        user=UserModel.objects.create_user(
            email='verifyuser@example.com',
            password='securepassword'
        ),
        verification_code='654321'
    )
    serializer = EmailVerificationSerializer(email_verification)
    data = serializer.data
    assert data['verification_code'] == '654321'
