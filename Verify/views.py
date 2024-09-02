import uuid
import random
import datetime
import csv
import os
from django.utils import timezone
from datetime import date
from django.conf import settings
from django.core.mail import send_mail
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import UserModel, EmailVerification
from .serializers import (
    UserRegistrationSerializer, 
    #LoginSerializer,
    VerifyOTPSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailChangeSerializer,
    PasswordChangeSerializer,
    UserSerializer,
    EmailVerificationSerializer,
)
from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django_filters import rest_framework as filters



User = get_user_model()

class CustomPageNumberPagination(PageNumberPagination):
    page_size = 20  
    page_size_query_param = 'page_size'  
    max_page_size = 100 

class UserFilter(filters.FilterSet):
    phone_number = filters.CharFilter(lookup_expr='icontains')
    email = filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = UserModel
        fields = ['phone_number', 'email']

class RegisterViewSet(viewsets.ViewSet):
    queryset = UserModel.objects.filter(is_active=True)
    serializer_class = UserRegistrationSerializer
    permission_classes = [IsAuthenticated] 
    pagination_class = CustomPageNumberPagination
    filterset_class = UserFilter


    def create(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user, otp = serializer.save()  # Get user and OTP from serializer
            self.save_otp(user.email, otp)
            self.send_otp_email(user.username, user.email, otp)
            return Response({'message': 'Registration successful. OTP has been sent to your email.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def save_otp(self, email, otp):
        """Save the OTP to the database for the given email"""
        user = UserModel.objects.get(email=email)
        EmailVerification.objects.update_or_create(
            user=user,
            defaults={
                'verification_code': otp,
                'is_verified': False,
                'created_at': timezone.now()
            }
        )

    def send_otp_email(self, username, email, otp):
        """Send OTP to the user's email"""
        verification_link = self.get_verification_link(email, otp)
        send_mail(
            'Verify Your Email Address',
            f'Hi {username},\n\n'
            f'Your OTP code is {otp}. Verify your email by visiting the following link: {verification_link}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

    def get_verification_link(self, email, otp):
        """Generate a verification link"""
        verification_url = f"http://{settings.SITE_DOMAIN}/api/verify-otp/?email={email}&otp={otp}"
        return verification_url


class VerifyOTPViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            otp = serializer.validated_data.get('otp')

            try:
                user = UserModel.objects.get(email=email)
            except UserModel.DoesNotExist:
                return Response({'error': 'Email does not exist'}, status=status.HTTP_400_BAD_REQUEST)

            if (
                not user.is_active
                and user.otp == otp
                and user.otp_expiry
                and timezone.now() < user.otp_expiry
            ):
                user.is_active = True
                user.otp = None
                user.otp_expiry = None
                user.max_otp_try = settings.MAX_OTP_TRY
                user.otp_max_out = None
                user.save()
                return Response({
                "message": "Successfully verified the user.",
                'links': {
                    'login': f"http://{settings.SITE_DOMAIN}/api/token/",
                    'password_reset': f"http://{settings.SITE_DOMAIN}/api/password-reset/"
                }
            }, status=status.HTTP_200_OK)
            return Response({
            "error": "User is already active or incorrect OTP. Please try again.",
            'links': {
                'register': f"http://{settings.SITE_DOMAIN}/register/",
                'password_reset': f"http://{settings.SITE_DOMAIN}/api/password-reset/"
            }
        }, status=status.HTTP_400_BAD_REQUEST)  
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

     
class RegenerateOTPViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access

    def regenerate_otp(self, request, pk=None):
        try:
            user = UserModel.objects.get(pk=pk)
        except UserModel.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if int(user.max_otp_try) == 0 and timezone.now() < user.otp_max_out:
            return Response({'error': 'Max OTP try reached, try after an hour'}, status=status.HTTP_400_BAD_REQUEST)

        otp = random.randint(1000, 9999)
        otp_expiry = timezone.now() + datetime.timedelta(minutes=10)
        max_otp_try = int(user.max_otp_try) - 1

        user.otp = otp
        user.otp_expiry = otp_expiry
        user.max_otp_try = max_otp_try

        if max_otp_try == 0:
            otp_max_out = timezone.now() + datetime.timedelta(hours=1)
            user.otp_max_out = otp_max_out
        elif max_otp_try == -1:
            user.max_otp_try = settings.MAX_OTP_TRY
        else:
            user.otp_max_out = None
            user.max_otp_try = max_otp_try

        user.save()

        self.send_otp_email(user.email, otp)

        return Response({
            'message': 'Successfully generated new OTP.',
            'links': {
                'verify_otp': f"http://{settings.SITE_DOMAIN}/verify-otp/",
                'login': f"http://{settings.SITE_DOMAIN}/api/token/"
            }
        }, status=status.HTTP_200_OK)

    def send_otp_email(self, email, otp):
        """Send OTP to the user's email"""
        send_mail(
            'Your OTP Code',
            f'Your new OTP code is {otp}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )


class LoginViewSet(viewsets.ViewSet):
    def create(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")

            user = authenticate(email=email, password=password)
            if user is not None:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'links': {
                    'verify_otp': f"http://{settings.SITE_DOMAIN}/verify-otp/",
                    'password_reset': f"http://{settings.SITE_DOMAIN}/api/password-reset/"
                    }
                })
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def create(self, request):
        try:
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()  # Ensure you have enabled blacklist in settings
            return Response({
                "detail": "Successfully logged out.",
                'links': {
                    'register': f"http://{settings.SITE_DOMAIN}/api/register/",
                    'login': f"http://{settings.SITE_DOMAIN}/api/token/",
                    'password_reset': f"http://{settings.SITE_DOMAIN}/api/password-reset/"
                }
            }, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestViewSet(viewsets.ViewSet):
    def create(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = UserModel.objects.get(email=email)
            except UserModel.DoesNotExist:
                return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

            token = uuid.uuid4()
            user.reset_password_token = token
            user.reset_password_token_expiry = timezone.now() + datetime.timedelta(hours=1)
            user.save()

            reset_link = f"http://{settings.SITE_DOMAIN}/api/password-reset/confirm/?token={token}"
            send_mail(
                'Password Reset Request',
                f'Use this link to reset your password: {reset_link}',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )

            return Response({
                "detail": "Password reset link sent to email.",
                'links': {
                    'password-reset-confirm': f"http://{settings.SITE_DOMAIN}/api/password-reset-confirm/"
                }
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmViewSet(viewsets.ViewSet):
    def create(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']

            try:
                user = UserModel.objects.get(
                    reset_password_token=token, 
                    reset_password_token_expiry__gte=timezone.now()
                )
            except UserModel.DoesNotExist:
                return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(new_password)
            user.reset_password_token = None
            user.reset_password_token_expiry = None
            user.save()

            return Response({
                "detail": "Password has been reset successfully.",
                'links': {
                    'login': f"http://{settings.SITE_DOMAIN}/api/token/"
                }
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailChangeViewSet(viewsets.ViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            user = request.user
            UserModel.objects.filter(user=user).delete()
            email_new = serializer.validated_data['email']

            try:
                user_with_email = get_user_model().objects.get(email=email_new)
                if user_with_email.is_verified:
                    return Response({'detail': _('Email address already taken.')}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    raise get_user_model().DoesNotExist

            except get_user_model().DoesNotExist:
                email_change_code = UserModel.objects.create_email_change_code(user, email_new)
                email_change_code.send_email_change_emails()
                return Response({'email': email_new}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailChangeVerifyViewSet(viewsets.ViewSet):
    permission_classes = (AllowAny,)

    def retrieve(self, request, *args, **kwargs):
        code = request.GET.get('code', '')
        try:
            email_change_code = UserModel.objects.get(code=code)
            delta = date.today() - email_change_code.created_at.date()
            if delta.days > UserModel.objects.get_expiry_period():
                email_change_code.delete()
                raise UserModel.DoesNotExist()

            try:
                user_with_email = get_user_model().objects.get(email=email_change_code.email)
                if user_with_email.is_verified:
                    email_change_code.delete()
                    return Response({'detail': _('Email address already taken.')}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    user_with_email.delete()
            except get_user_model().DoesNotExist:
                pass

            email_change_code.user.email = email_change_code.email
            email_change_code.user.save()
            email_change_code.delete()
            return Response({'success': _('Email address changed.')}, status=status.HTTP_200_OK)
        except UserModel.DoesNotExist:
            return Response({'detail': _('Unable to verify user.')}, status=status.HTTP_400_BAD_REQUEST)

class PasswordChangeViewSet(viewsets.ViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordChangeSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            user = request.user
            password = serializer.validated_data['password']
            user.set_password(password)
            user.save()
            return Response({'success': _('Password changed.')}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserMeViewSet(viewsets.ViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer

    def list(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data)



class UserCSVExportView(APIView):
    def get(self, request, *args, **kwargs):
        """
        API view to generate a CSV file with user data and return it as a response.
        """
        file_name = "usersname.csv"
        file_path = os.path.join(settings.BASE_DIR, file_name)

        users = UserModel.objects.all()

        
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Username', 'Email', 'Is Active', 'Date Registered'])
            for user in users:
                writer.writerow([
                    user.username,
                    user.email,
                    user.is_active,
                    user.user_registered_at
                ])
        
        return Response({"message": f"CSV file '{file_name}' has been created successfully."}, status=status.HTTP_200_OK)
        


class EmailVerificationViewSet(viewsets.ViewSet):
    def create(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['verification_code']
            try:
                verification = EmailVerification.objects.get(verification_code=code)
                if verification.is_verified:
                    return Response({'detail': 'Email already verified.'}, status=status.HTTP_400_BAD_REQUEST)
                user = verification.user
                if timezone.now() > user.otp_expiry:
                    return Response({'detail': 'OTP expired.'}, status=status.HTTP_400_BAD_REQUEST)
                verification.is_verified = True
                verification.save()
                user.is_active = True
                user.save()
                return Response({'detail': 'Email verified successfully.'}, status=status.HTTP_200_OK)
            except EmailVerification.DoesNotExist:
                return Response({'detail': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)