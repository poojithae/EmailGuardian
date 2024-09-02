from django.contrib import admin
from .models import UserModel, UserProfile, EmailVerification

@admin.register(UserModel)
class UserModelAdmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'is_active', 'is_staff', 'user_registered_at')
    search_fields = ('email', 'username')
    list_filter = ('is_active', 'is_staff')
    ordering = ('-user_registered_at',)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'first_name', 'last_name', 'address')
    search_fields = ('user__email', 'first_name', 'last_name')
    list_filter = ('user',)

@admin.register(EmailVerification)
class EmailVerificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'verification_code', 'is_verified', 'created_at')
    search_fields = ('user__email', 'verification_code')
    list_filter = ('is_verified', 'created_at')
    ordering = ('-created_at',)
