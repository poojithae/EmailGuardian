# import pytest
# from django.urls import reverse, resolve
# from rest_framework import status
# from rest_framework.test import APIClient

# @pytest.mark.django_db
# class TestURLs:
#     def setup_method(self):
#         self.client = APIClient()

#     def test_register_url(self):
#         url = reverse('register-list')
#         response = self.client.get(url)
#         assert response.status_code == status.HTTP_200_OK
#         assert resolve(url).view_name == 'register-list'

#     # def test_verify_otp_url(self):
#     #     url = reverse('verify-otp-list')
#     #     response = self.client.get(url)
#     #     assert response.status_code == status.HTTP_200_OK
#     #     assert resolve(url).view_name == 'verify-otp-list'

#     # def test_regenerate_otp_url(self):
#     #     url = reverse('regenerate-otp-list')
#     #     response = self.client.get(url)
#     #     assert response.status_code == status.HTTP_200_OK
#     #     assert resolve(url).view_name == 'regenerate-otp-list'

#     # def test_password_reset_url(self):
#     #     url = reverse('password-reset-list')
#     #     response = self.client.get(url)
#     #     assert response.status_code == status.HTTP_200_OK
#     #     assert resolve(url).view_name == 'password-reset-list'

#     # def test_password_reset_confirm_url(self):
#     #     url = reverse('password-reset-confirm-list')
#     #     response = self.client.get(url)
#     #     assert response.status_code == status.HTTP_200_OK
#     #     assert resolve(url).view_name == 'password-reset-confirm-list'

#     # def test_logout_url(self):
#     #     url = reverse('logout-list')
#     #     response = self.client.get(url)
#     #     assert response.status_code == status.HTTP_200_OK
#     #     assert resolve(url).view_name == 'logout-list'

#     # def test_email_verification_url(self):
#     #     url = reverse('email-verification-list')
#     #     response = self.client.get(url)
#     #     assert response.status_code == status.HTTP_200_OK
#     #     assert resolve(url).view_name == 'email-verification-list'

#     # def test_token_obtain_pair_url(self):
#     #     url = reverse('token_obtain_pair')
#     #     response = self.client.post(url, {'username': 'testuser', 'password': 'testpass'})
#     #     assert response.status_code == status.HTTP_200_OK
#     #     assert 'access' in response.data
#     #     assert 'refresh' in response.data

#     # def test_token_refresh_url(self):
#     #     url = reverse('token_refresh')
#     #     response = self.client.post(url, {'refresh': 'dummy_refresh_token'})
#     #     assert response.status_code == status.HTTP_200_OK
#     #     assert 'access' in response.data

#     # def test_export_csv_url(self):
#     #     url = reverse('export-csv')
#     #     response = self.client.get(url)
#     #     assert response.status_code == status.HTTP_200_OK
#     #     assert 'text/csv' in response['Content-Type']
