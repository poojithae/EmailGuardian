import pytest
from django.utils import timezone
from django.core.exceptions import ValidationError
from Verify.models import UserModel, UserProfile, EmailVerification

@pytest.mark.django_db
class TestUserModel:

    def test_create_user(self):
        user = UserModel.objects.create_user(
        email="userx@gmail.com",
        password="password123"
        )
        assert user.email == "userx@gmail.com"
        assert user.check_password("password123")
        assert user.is_active is False
        assert not user.is_staff

    def test_create_superuser(self):
        user = UserModel.objects.create_superuser(
        email="admin@gmail.com",
        password="adminpassword"
        )
        assert user.email == "admin@gmail.com"
        assert user.check_password("adminpassword")
        assert user.is_active is True
        assert user.is_staff is True
        assert user.is_superuser is True

    # def test_email_validation(self):
    #     with pytest.raises(ValidationError):
    #         user = UserModel(
    #             email='userx@gmail.com',
    #             password='password123'
    #         )  
    #         user.full_clean()  # This will trigger validation

    def test_otp_expiry(self):
        now = timezone.now()
        user = UserModel(email='userx@gmail.com', password='password123', otp_expiry=now)
        user.set_password('password123')  # Ensure password is hashed
        user.save()
        user.refresh_from_db()  # Refresh to get the latest data
        assert user.otp_expiry == now

@pytest.mark.django_db
def test_user_profile_creation():
    user = UserModel.objects.create_user(
        email="userx@gmail.com",
        password="profilepassword"
    )
    profile = UserProfile.objects.create(
        user=user,
        first_name="Mahatma",
        last_name="Gandhi",
        address="123 Test St"
    )
    assert profile.user == user
    assert profile.first_name == "Mahatma"
    assert profile.last_name == "Gandhi"
    assert profile.address == "123 Test St"

@pytest.mark.django_db
def test_email_verification_creation():
    user = UserModel.objects.create_user(
        email="verifyuser@gmail.com",
        password="verifypassword"
    )
    email_verification = EmailVerification.objects.create(
        user=user,
        verification_code="123456"
    )
    assert email_verification.user == user
    assert email_verification.verification_code == "123456"
    assert email_verification.is_verified == False
    assert email_verification.created_at <= timezone.now()

