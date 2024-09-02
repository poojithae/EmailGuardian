from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.core.validators import RegexValidator, validate_email
from django.db import models



phone_regex = RegexValidator(
    regex=r"^\d{10}$", 
    message="Phone number must be 10 digits only."
)

class UserManager(BaseUserManager):
    def create_user(self, email, password=None):
        if not email:
            raise ValueError("Users must have an email address")
        
        email = self.normalize_email(email)
        user = self.model(email=email)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        user = self.create_user(
            email=email, password=password
        )
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class UserModel(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(
        unique=True,
        max_length=255,
        validators=[validate_email],
        db_index=True,
    )
    phone_number = models.CharField(
        unique=True,
        max_length=10,
        null=True,
        blank=True,
        validators=[phone_regex],
        db_index=True,
    )
    username = models.CharField(max_length=30, blank=True, null=True)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)
    max_otp_try = models.CharField(max_length=2, default=settings.MAX_OTP_TRY)
    otp_max_out = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    user_registered_at = models.DateTimeField(auto_now_add=True)
    reset_password_token = models.CharField(max_length=255, blank=True, null=True, unique=False)
    reset_password_token_expiry = models.DateTimeField(blank=True, null=True)
    
    
    USERNAME_FIELD = "email"
    

    objects = UserManager()

    def __str__(self):
        return self.email
    
    class Meta:
        permissions = [
            ("view_user", "Can view user"),
        ]

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['email'], name='unique_email'),
            models.UniqueConstraint(fields=['phone_number'], name='unique_phone_number'),
        ]


class UserProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        primary_key=True,
        null=False, blank=False,
    )
    first_name = models.CharField(max_length=50, null=False, blank=False)
    last_name = models.CharField(max_length=50, null=False, blank=False)
    address = models.TextField(null=False, blank=False)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

class EmailVerification(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )
    verification_code = models.CharField(max_length=6)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Verification for {self.user.email}"

