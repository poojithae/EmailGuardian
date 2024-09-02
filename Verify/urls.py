from django.urls import path, include
from .views import (
    RegisterViewSet,
    VerifyOTPViewSet,
    RegenerateOTPViewSet,
    PasswordResetRequestViewSet,
    PasswordResetConfirmViewSet,
    LogoutViewSet,
    EmailChangeViewSet,
    EmailChangeVerifyViewSet,
    PasswordChangeViewSet,
    UserMeViewSet,
    EmailVerificationViewSet,
    
)
from .views import UserCSVExportView
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt import views as jwt_views


router = DefaultRouter()
router.register(r'register', RegisterViewSet, basename='register')
router.register(r'verify-otp', VerifyOTPViewSet, basename='verify-otp')
router.register(r'regenerate-otp', RegenerateOTPViewSet, basename='regenerate-otp')
router.register(r'password-reset', PasswordResetRequestViewSet, basename='password-reset')
router.register(r'password-reset-confirm', PasswordResetConfirmViewSet, basename='password-reset-confirm')
router.register(r'logout', LogoutViewSet, basename='logout')
router.register(r'email-change', EmailChangeViewSet, basename='email-change')
router.register(r'email-change-verify', EmailChangeVerifyViewSet, basename='email-change-verify')
router.register(r'password-change', PasswordChangeViewSet, basename='password-change')
router.register(r'user-me', UserMeViewSet, basename='user-me')
router.register(r'email-verification', EmailVerificationViewSet, basename='email-verification')



urlpatterns = [
    path('', include(router.urls)),
    #path('regenerate-otp/<int:user_id>/', RegenerateOTPViewSet.as_view(), name='regenerate-otp'),
    path('token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('export-csv/', UserCSVExportView.as_view(), name='export-csv'),
    
]
