from django.contrib import admin
from .models import UserModel

@admin.register(UserModel)
class UserModelAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_verified', 'is_staff', 'user_registered_at')
    search_fields = ('email', 'first_name', 'last_name', 'phone_number')
    list_filter = ('is_active', 'is_staff')
    ordering = ('-user_registered_at',)

# @admin.register(UserProfile)
# class UserProfileAdmin(admin.ModelAdmin):
#     list_display = ('user', 'first_name', 'last_name', 'address')
#     search_fields = ('user__email', 'first_name', 'last_name')
#     list_filter = ('user',)

# @admin.register(EmailVerification)
# class EmailVerificationAdmin(admin.ModelAdmin):
#     list_display = ('user', 'verification_code', 'is_verified', 'created_at')
#     search_fields = ('user__email', 'verification_code')
#     list_filter = ('is_verified', 'created_at')
#     ordering = ('-created_at',)





# from django.contrib import admin
# from .models import UserModel
# #, UserProfile, EmailVerification

# @admin.register(UserModel)
# class UserModelAdmin(admin.ModelAdmin):
#     list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_verified', 'is_staff', 'user_registered_at')
#     search_fields = ('email', 'first_name', 'last_name', 'phone_number')
#     list_filter = ('is_active', 'is_staff')
#     ordering = ('-user_registered_at',)

# @admin.register(UserProfile)
# class UserProfileAdmin(admin.ModelAdmin):
#     list_display = ('user', 'first_name', 'last_name', 'address')
#     search_fields = ('user__email', 'first_name', 'last_name')
#     list_filter = ('user',)

# @admin.register(EmailVerification)
# class EmailVerificationAdmin(admin.ModelAdmin):
#     list_display = ('user', 'verification_code', 'is_verified', 'created_at')
#     search_fields = ('user__email', 'verification_code')
#     list_filter = ('is_verified', 'created_at')
#     ordering = ('-created_at',)


# from django.contrib import admin
# from .models import UserModel, SignupCode, PasswordResetCode, EmailChangeCode

# class UserModelAdmin(admin.ModelAdmin):
#     list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_verified', 'is_staff', 'user_registered_at')
#     search_fields = ('email', 'first_name', 'last_name', 'phone_number')
#     list_filter = ('is_active', 'is_verified', 'is_staff')
#     ordering = ('-user_registered_at',)
#     readonly_fields = ('user_registered_at', 'otp_expiry', 'otp_max_out', 'reset_password_token', 'reset_password_token_expiry')

# class SignupCodeAdmin(admin.ModelAdmin):
#     list_display = ('user', 'otp', 'ipaddr', 'created_at')
#     search_fields = ('user__email', 'otp', 'ipaddr')
#     list_filter = ('created_at',)
#     readonly_fields = ('created_at',)

# class PasswordResetCodeAdmin(admin.ModelAdmin):
#     list_display = ('user', 'otp', 'created_at')
#     search_fields = ('user__email', 'otp')
#     list_filter = ('created_at',)
#     readonly_fields = ('created_at',)

# class EmailChangeCodeAdmin(admin.ModelAdmin):
#     list_display = ('user', 'otp', 'email', 'created_at')
#     search_fields = ('user__email', 'otp', 'email')
#     list_filter = ('created_at',)
#     readonly_fields = ('created_at',)

# # Registering models with the admin site
# admin.site.register(UserModel, UserModelAdmin)
# admin.site.register(SignupCode, SignupCodeAdmin)
# admin.site.register(PasswordResetCode, PasswordResetCodeAdmin)
# admin.site.register(EmailChangeCode, EmailChangeCodeAdmin)
