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
from .models import UserModel, PasswordResetCode, EmailChangeCode
from .serializers import (
    UserRegistrationSerializer, 
    #LoginSerializer,
    VerifyOTPSerializer,
    PasswordResetSerializer,
    PasswordResetVerifiedSerializer,
    PasswordChangeSerializer,
    EmailChangeSerializer,
    #EmailChangeVerifySerializer
)
from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django_filters import rest_framework as filters
from rest_framework.throttling import UserRateThrottle
from django.core.cache import cache



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

class BurstRateThrottle(UserRateThrottle):
    rate = '100/minute'


class RegisterViewSet(viewsets.ViewSet):
    queryset = UserModel.objects.filter(is_active=True)
    serializer_class = UserRegistrationSerializer
    permission_classes = [IsAuthenticated] 
    pagination_class = CustomPageNumberPagination
    filterset_class = UserFilter


    def create(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user, otp = serializer.save()  
            self.save_otp(user.email, otp)
            self.send_otp_email(user.username, user.email, otp)
            return Response({'message': 'Registration successful. OTP has been sent to your email.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def send_otp_email(self, first_name, email, otp):
        """Send OTP to the user's email"""
        verification_link = self.get_verification_link(email, otp)
        send_mail(
            'Verify Your Email Address',
            f'Hi {first_name},\n\n'
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
    permission_classes = (AllowAny,)
    serializer_class = UserRegistrationSerializer

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
    permission_classes = [IsAuthenticated,]

    def create(self, request):
        try:
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()  
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


class PasswordResetViewSet(viewsets.ViewSet):
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetSerializer

    def create(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = cache.get(f'user_{email}')

            if not user:
                try:
                    user = UserModel.objects.get(email=email)
                    cache.set(f'user_{email}', user, timeout=60*60)  
                except get_user_model().DoesNotExist:
                    pass

            if user and user.is_verified and user.is_active:
                PasswordResetCode.objects.filter(user=user).delete()
                password_reset_code = PasswordResetCode.objects.create_password_reset_code(user)
                reset_link = f"http://{settings.SITE_DOMAIN}/api/password-reset/verify/?code={password_reset_code.token}"
                send_mail(
                    'Password Reset Request',
                    f'Use this link to reset your password: {reset_link}',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )

                return Response({'email': email}, status=status.HTTP_201_CREATED)

            return Response({'detail': 'Password reset not allowed.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetVerifyViewSet(viewsets.ViewSet):
    permission_classes = (AllowAny,)

    def retrieve(self, request):
        token = request.GET.get('token', '')

        try:
            password_reset_code = PasswordResetCode.objects.get(token=token)

            if (timezone.now() - password_reset_code.created_at).days > PasswordResetCode.objects.get_expiry_period():
                password_reset_code.delete()
                raise PasswordResetCode.DoesNotExist()

            return Response({'success': 'Password reset code is valid.'}, status=status.HTTP_200_OK)

        except PasswordResetCode.DoesNotExist:
            return Response({'detail': 'Invalid or expired password reset code.'}, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetVerifiedViewSet(viewsets.ViewSet):
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetVerifiedSerializer

    def create(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            token = serializer.validated_data['token']
            password = serializer.validated_data['password']

            try:
                password_reset_code = PasswordResetCode.objects.get(token=token)
                user = password_reset_code.user
                user.set_password(password)
                user.save()

                # Delete password reset code just used
                password_reset_code.delete()

                return Response({'success': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)

            except PasswordResetCode.DoesNotExist:
                return Response({'detail': 'Invalid or expired password reset code.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailChangeViewSet(viewsets.ViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeSerializer

    def create(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = request.user
            email_new = serializer.validated_data['email']

            EmailChangeCode.objects.filter(user=user).delete()

            try:
                user_with_email = UserModel.objects.get(email=email_new)
                if user_with_email.is_verified:
                    return Response({'detail': 'Email address already taken.'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    raise UserModel.DoesNotExist

            except UserModel.DoesNotExist:
                email_change_code = EmailChangeCode.objects.create_email_change_code(user, email_new)
                change_link = f"http://{settings.SITE_DOMAIN}/api/email-change/verify/?code={email_change_code.token}"
                send_mail(
                    'Email Change Request',
                    f'Use this link to confirm your email change: {change_link}',
                    settings.DEFAULT_FROM_EMAIL,
                    [email_new],
                    fail_silently=False,
                )

                return Response({'email': email_new}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailChangeVerifyViewSet(viewsets.ViewSet):
    permission_classes = (AllowAny,)

    def retrieve(self, request):
        token = request.GET.get('token', '')

        try:
            email_change_code = EmailChangeCode.objects.get(token=token)

            if (timezone.now() - email_change_code.created_at).days > EmailChangeCode.objects.get_expiry_period():
                email_change_code.delete()
                raise EmailChangeCode.DoesNotExist()

            try:
                user_with_email = UserModel.objects.get(email=email_change_code.email)
                if user_with_email.is_verified:
                    email_change_code.delete()
                    return Response({'detail': 'Email address already taken.'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    user_with_email.delete()
            except UserModel.DoesNotExist:
                pass
            
            email_change_code.user.email = email_change_code.email
            email_change_code.user.save()

            email_change_code.delete()

            return Response({'success': 'Email address changed successfully.'}, status=status.HTTP_200_OK)

        except EmailChangeCode.DoesNotExist:
            return Response({'detail': 'Invalid or expired email change code.'}, status=status.HTTP_400_BAD_REQUEST)


class PasswordChangeViewSet(viewsets.ViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordChangeSerializer

    def create(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = request.user
            password = serializer.validated_data['password']
            user.set_password(password)
            user.save()

            return Response({'success': 'Password changed successfully.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



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


