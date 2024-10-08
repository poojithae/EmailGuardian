from rest_framework import serializers
from .models import UserModel
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import random
import string
from .utils import send_otp
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from .models import PasswordResetCode, EmailChangeCode
 
User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ('email', 'phone_number', 'username', 'is_active')


class UserRegistrationSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True, style={'input_type': 'password'})
    password2 = serializers.CharField(write_only=True, style={'input_type': 'password'})

    class Meta:
        model = UserModel
        fields = ['username', 'email', 'password1', 'password2' ]

    def validate(self, data):
        """
        Check that the two passwords match.
        """
        password1 = data.get('password1')
        password2 = data.get('password2')

        if data['password1'] != data['password2']:
            raise serializers.ValidationError("Passwords must match.")
        return data

    def create(self, validated_data):
        otp = ''.join(random.choices(string.digits, k=6))  # Generate a 6-digit OTP
        otp_expiry = timezone.now() + timezone.timedelta(minutes=60)

        user = UserModel(
            email=validated_data["email"],
            username=validated_data.get("username"),
            otp=otp,
            otp_expiry=otp_expiry,
            max_otp_try=settings.MAX_OTP_TRY
        )
        user.set_password(validated_data["password1"])
        user.save()

        return user, otp
    
   
class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise ValidationError("No user with this email address.")
        return value
    
class PasswordResetVerifiedSerializer(serializers.Serializer):
    token = serializers.UUIDField()
    password = serializers.CharField(max_length=128)

    def validate_code(self, value):
        
        if not PasswordResetCode.objects.filter(token=value).exists():
            raise ValidationError("Invalid or expired reset code.")
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        return value

    def validate(self, data):
        if 'password' in data and 'confirm_password' in data and data['password'] != data['confirm_password']:
            raise ValidationError("Passwords do not match.")
        return data

class PasswordChangeSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128)

    def validate_password(self, value):
        if len(value) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        return value


class EmailChangeSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise ValidationError("No user with this email address.")
        return value

class EmailChangeVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate_email(self, value):
        if not EmailChangeCode.objects.filter(email=value).exists():
            raise ValidationError("No pending email change request for this email address.")
        return value
    





class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.UUIDField()
    new_password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise ValidationError("Passwords do not match.")
        return data

class EmailChangeSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)


class EmailChangeVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

class PasswordChangeSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128)    


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'first_name', 'last_name')




# class EmailVerificationSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = EmailVerification
#         fields = ['verification_code']