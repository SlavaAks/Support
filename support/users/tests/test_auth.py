from django.test import TestCase

# Create your tests here.


import pytest

from users.models import User

from django.test import TestCase

from tickets.models import Ticket

from rest_framework_jwt.compat import get_user_model

User = get_user_model()


@pytest.mark.django_db
class Test_action_with_model(TestCase):
    """JSON Web Token Authentication"""

    def setUp(self):
        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)

    def test_create_user(self):
        self.assertEqual(User.objects.get_by_natural_key(username='jpueblo'), self.user)

    def test_ticket_create(self):
        self.topic = "uuurururururu"
        self.description = "uruuutuuiiirkkfkfkfkf"
        self.ticket = Ticket.objects.create(user=self.user, topic=self.topic, description=self.description)
        self.assertEqual(Ticket.objects.get(topic='uuurururururu'), self.ticket)
        self.assertEqual(Ticket.objects.get(topic='uuurururururu').status, 'unsolved')

    # def test_post_json_passing_jwt_auth(self):
    #     """
    #     Ensure POSTing JSON over JWT auth with correct credentials
    #     passes and does not require CSRF
    #     """
    #     payload = utils.jwt_payload_handler(self.user)
    #     token = utils.jwt_encode_handler(payload)
    #
    #     auth = 'JWT {0}'.format(token)
    #     response = self.csrf_client.post(
    #         '/jwt/', {'example': 'example'},
    #         HTTP_AUTHORIZATION=auth, format='json')
    #
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #
    # def test_post_form_failing_jwt_auth(self):
    #     """
    #     Ensure POSTing form over JWT auth without correct credentials fails
    #     """
    #     response = self.csrf_client.post('/jwt/', {'example': 'example'})
    #     self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    #     self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')
    #
    # def test_post_json_failing_jwt_auth(self):
    #     """
    #     Ensure POSTing json over JWT auth without correct credentials fails
    #     """
    #     response = self.csrf_client.post('/jwt/', {'example': 'example'},
    #                                      format='json')
    #     self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    #     self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')
    #
    # def test_post_no_jwt_header_failing_jwt_auth(self):
    #     """
    #     Ensure POSTing over JWT auth without credentials fails
    #     """
    #     auth = 'JWT'
    #     response = self.csrf_client.post(
    #         '/jwt/', {'example': 'example'},
    #         HTTP_AUTHORIZATION=auth, format='json')
    #
    #     msg = 'Invalid Authorization header. No credentials provided.'
    #
    #     self.assertEqual(response.data['detail'], msg)
    #     self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    #     self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')
    #
    # def test_post_invalid_jwt_header_failing_jwt_auth(self):
    #     """
    #     Ensure POSTing over JWT auth without correct credentials fails
    #     """
    #     auth = 'JWT abc abc'
    #     response = self.csrf_client.post(
    #         '/jwt/', {'example': 'example'},
    #         HTTP_AUTHORIZATION=auth, format='json')
    #
    #     msg = ('Invalid Authorization header. Credentials string '
    #            'should not contain spaces.')
    #
    #     self.assertEqual(response.data['detail'], msg)
    #     self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    #     self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')
    #
    # def test_post_expired_token_failing_jwt_auth(self):
    #     """
    #     Ensure POSTing over JWT auth with expired token fails
    #     """
    #     payload = utils.jwt_payload_handler(self.user)
    #     payload['exp'] = 1
    #     token = utils.jwt_encode_handler(payload)
    #
    #     auth = 'JWT {0}'.format(token)
    #     response = self.csrf_client.post(
    #         '/jwt/', {'example': 'example'},
    #         HTTP_AUTHORIZATION=auth, format='json')
    #
    #     msg = 'Signature has expired.'
    #
    #     self.assertEqual(response.data['detail'], msg)
    #     self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    #     self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')
    #
    # @override_settings(AUTH_USER_MODEL='tests.CustomUser')
    # def test_post_form_failing_jwt_auth_changed_user_secret_key(self):
    #     """
    #     Ensure changin secret key on USER level makes tokens invalid
    #     """
    #     # fine tune settings
    #     api_settings.JWT_GET_USER_SECRET_KEY = get_jwt_secret
    #
    #     tmp_user = User.objects.create(email='b@example.com')
    #     payload = utils.jwt_payload_handler(tmp_user)
    #     token = utils.jwt_encode_handler(payload)
    #
    #     auth = 'JWT {0}'.format(token)
    #     response = self.csrf_client.post(
    #         '/jwt/', {'example': 'example'}, HTTP_AUTHORIZATION=auth, format='json')
    #
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #
    #     # change token, verify
    #     tmp_user.jwt_secret = uuid.uuid4()
    #     tmp_user.save()
    #
    #     response = self.csrf_client.post(
    #         '/jwt/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)
    #
    #     self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    #
    #     # revert api settings
    #     api_settings.JWT_GET_USER_SECRET_KEY = DEFAULTS['JWT_GET_USER_SECRET_KEY']
    #
    # def test_post_invalid_token_failing_jwt_auth(self):
    #     """
    #     Ensure POSTing over JWT auth with invalid token fails
    #     """
    #     auth = 'JWT abc123'
    #     response = self.csrf_client.post(
    #         '/jwt/', {'example': 'example'},
    #         HTTP_AUTHORIZATION=auth, format='json')
    #
    #     msg = 'Error decoding signature.'
    #
    #     self.assertEqual(response.data['detail'], msg)
    #     self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    #     self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')
    #
    # @unittest.skipUnless(oauth2_provider, DJANGO_OAUTH2_PROVIDER_NOT_INSTALLED)
    # def test_post_passing_jwt_auth_with_oauth2_priority(self):
    #     """
    #     Ensure POSTing over JWT auth with correct credentials
    #     passes and does not require CSRF when OAuth2Authentication
    #     has priority on authentication_classes
    #     """
    #     payload = utils.jwt_payload_handler(self.user)
    #     token = utils.jwt_encode_handler(payload)
    #
    #     auth = 'JWT {0}'.format(token)
    #     response = self.csrf_client.post(
    #         '/oauth2-jwt/', {'example': 'example'},
    #         HTTP_AUTHORIZATION=auth, format='json')
    #
    #     self.assertEqual(response.status_code, status.HTTP_200_OK, response)
    #
    # @unittest.skipUnless(oauth2_provider, DJANGO_OAUTH2_PROVIDER_NOT_INSTALLED)
    # def test_post_passing_oauth2_with_jwt_auth_priority(self):
    #     """
    #     Ensure POSTing over OAuth2 with correct credentials
    #     passes and does not require CSRF when JSONWebTokenAuthentication
    #     has priority on authentication_classes
    #     """
    #     Client = oauth2_provider.oauth2.models.Client
    #     AccessToken = oauth2_provider.oauth2.models.AccessToken
    #
    #     oauth2_client = Client.objects.create(
    #         user=self.user,
    #         client_type=0,
    #     )
    #
    #     access_token = AccessToken.objects.create(
    #         user=self.user,
    #         client=oauth2_client,
    #     )
    #
    #     auth = 'Bearer {0}'.format(access_token.token)
    #     response = self.csrf_client.post(
    #         '/jwt-oauth2/', {'example': 'example'},
    #         HTTP_AUTHORIZATION=auth, format='json')
    #
    #     self.assertEqual(response.status_code, status.HTTP_200_OK, response)
    #
    # def test_post_form_passing_jwt_invalid_payload(self):
    #     """
    #     Ensure POSTing json over JWT auth with invalid payload fails
    #     """
    #     payload = dict(email=None)
    #     token = utils.jwt_encode_handler(payload)
    #
    #     auth = 'JWT {0}'.format(token)
    #     response = self.csrf_client.post(
    #         '/jwt/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)
    #
    #     msg = 'Invalid payload.'
    #
    #     self.assertEqual(response.data['detail'], msg)
    #     self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    #
    # def test_different_auth_header_prefix(self):
    #     """
    #     Ensure using a different setting for `JWT_AUTH_HEADER_PREFIX` and
    #     with correct credentials passes.
    #     """
    #     api_settings.JWT_AUTH_HEADER_PREFIX = 'Bearer'
    #
    #     payload = utils.jwt_payload_handler(self.user)
    #     token = utils.jwt_encode_handler(payload)
    #
    #     auth = 'Bearer {0}'.format(token)
    #     response = self.csrf_client.post(
    #         '/jwt/', {'example': 'example'},
    #         HTTP_AUTHORIZATION=auth, format='json')
    #
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #
    #     # Restore original settings
    #     api_settings.JWT_AUTH_HEADER_PREFIX = DEFAULTS['JWT_AUTH_HEADER_PREFIX']
    #
    # def test_post_form_failing_jwt_auth_different_auth_header_prefix(self):
    #     """
    #     Ensure using a different setting for `JWT_AUTH_HEADER_PREFIX` and
    #     POSTing form over JWT auth without correct credentials fails and
    #     generated correct WWW-Authenticate header
    #     """
    #     api_settings.JWT_AUTH_HEADER_PREFIX = 'Bearer'
    #
    #     response = self.csrf_client.post('/jwt/', {'example': 'example'})
    #     self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    #     self.assertEqual(response['WWW-Authenticate'], 'Bearer realm="api"')
    #
    #     # Restore original settings
    #     api_settings.JWT_AUTH_HEADER_PREFIX = DEFAULTS['JWT_AUTH_HEADER_PREFIX']

# import pytest
# import pytz
# import re
# from datetime import timedelta
# from django import VERSION as DJANGO_VERSION
# from django.conf import settings
# from django.urls import reverse
# from django.core import mail
# from django.utils.timezone import datetime
# from rest_framework.test import APIClient

# @pytest.mark.django_db
# def test_login_fail(api_client):
#     login_url = reverse('shop:login')
#     data = {
#         'form_data': {
#             'username': 'a',
#             'password': 'b',
#         }
#     }
#     response = api_client.post(login_url, data, format='json')
#     assert response.status_code == 400
#     assert response.json() == {'login_form': {'non_field_errors': ['Unable to log in with provided credentials.']}}
#     assert response.cookies.get('sessionid') is None
# from rest_framework_jwt.views import obtain_jwt_token
#
#
# @pytest.mark.django_db
# def test_login_success(api_client=APIClient()):  # registered_customer, api_client):
#     login_url = reverse(obtain_jwt_token)
#     data = {
#         "email": "aks8slava@mail.ru",
#         "password": "1801290037"
#     }
#
#     response = api_client.post(login_url, data, format='json')
#     # print("response.content")
#     print(data)
#     print(dir(response))
#     print(response.json)
#     print(response.data)
#     assert type(response.data) == type(dict)
#     assert True
# assert len(response.json().get('key')) == 40
# # session_cookie = response.cookies.get('sessionid')
# assert session_cookie['expires'] == ''
# assert session_cookie['max-age'] == ''


# @pytest.mark.django_db
# def test_login_presistent(registered_customer, api_client):
#     login_url = reverse('shop:login')
#     data = {
#         'form_data': {
#             'username': registered_customer.email,
#             'password': 'secret',
#             'stay_logged_in': True
#         }
#     }
#     response = api_client.post(login_url, data, format='json')
#     tz_gmt = pytz.timezone('GMT')
#     shall_expire = datetime.now(tz=tz_gmt).replace(microsecond=0) + timedelta(seconds=settings.SESSION_COOKIE_AGE)
#     assert response.status_code == 200
#     session_cookie = response.cookies.get('sessionid')
#     expires = datetime.strptime(session_cookie['expires'], '%a, %d %b %Y %H:%M:%S GMT')
#     expires = expires.replace(tzinfo=tz_gmt)
#     assert abs(expires - shall_expire) < timedelta(seconds=5)
#     assert session_cookie['max-age'] == settings.SESSION_COOKIE_AGE
#
#
# @pytest.mark.django_db
# def test_logout(registered_customer, api_client):
#     assert api_client.login(username=registered_customer.email, password='secret') is True
#     logout_url = reverse('shop:logout')
#     response = api_client.post(logout_url, {}, format='json')
#     assert response.status_code == 200
#     assert response.json() == {'logout_form': {'success_message': 'Successfully logged out.'}}
#
#
# @pytest.mark.django_db
# def test_change_password_fail(registered_customer, api_client):
#     assert api_client.login(username=registered_customer.email, password='secret') is True
#     change_url = reverse('shop:password-change')
#     data = {
#         'form_data': {
#             'new_password1': 'secret1',
#             'new_password2': 'secret2',
#         }
#     }
#     response = api_client.post(change_url, data, format='json')
#     assert response.status_code == 422
#     payload = response.json()
#     if DJANGO_VERSION < (3,):
#         assert payload == {'password_change_form': {'new_password2': ["The two password fields didn't match."]}}
#     else:
#         assert payload == {'password_change_form': {'new_password2': ["The two password fields didn’t match."]}}
#
#
# @pytest.mark.django_db
# def test_change_password_success(registered_customer, api_client):
#     api_client.login(username=registered_customer.email, password='secret')
#     change_url = reverse('shop:password-change')
#     data = {
#         'form_data': {
#             'new_password1': 'secret1',
#             'new_password2': 'secret1',
#         }
#     }
#     response = api_client.post(change_url, data, format='json')
#     assert response.status_code == 200
#     assert response.json() == {'password_change_form': {'success_message': 'Password has been changed successfully.'}}
#     api_client.logout()
#     assert api_client.login(username=registered_customer.email, password='secret') is False
#     assert api_client.login(username=registered_customer.email, password='secret1') is True
#
#
# @pytest.mark.django_db
# def test_password_reset(settings, registered_customer, api_client, api_rf):
#     settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
#     reset_request_url = reverse('shop:password-reset-request')
#     data = {
#         'form_data': {
#             'email': registered_customer.email,
#         }
#     }
#     response = api_client.post(reset_request_url, data, format='json')
#     assert response.status_code == 200
#     assert response.json() == {
#         'password_reset_request_form': {
#             'success_message': "Instructions on how to reset the password have been sent to 'admin@example.com'."
#         }
#     }
#     body_begin = "You're receiving this email because you requested a password reset for your user\naccount 'admin@example.com' at example.com."
#     assert len(mail.outbox) == 1
#     assert mail.outbox[0].body.startswith(body_begin)
#     matches = re.search(PasswordResetRequestSerializer.invalid_password_reset_confirm_url + r'([^/]+)/([0-9A-Za-z-]+)',
#                         mail.outbox[0].body)
#     assert matches
#     request = api_rf.get('/pasword-reset-confirm')
#     response = PasswordResetConfirmView.as_view()(request, uidb64=matches.group(1), token=matches.group(2))
#     assert response.status_code == 200
#     assert response.data == {'validlink': True, 'user_name': 'admin@example.com', 'form_name': 'password_reset_form'}
#     request = api_rf.post('/pasword-reset-confirm/', {'form_data': '__invalid__'})
#     response = PasswordResetConfirmView.as_view()(request, uidb64=matches.group(1), token=matches.group(2))
#     assert response.status_code == 422
#     assert response.data == {'password_reset_confirm_form': {'non_field_errors': ['Invalid POST data.']}}
#     data = {
#         'form_data': {
#             'new_password1': 'secret1',
#             'new_password2': 'secret1',
#         }
#     }
#     request = api_rf.post('/pasword-reset-confirm/', data, format='json')
#     response = PasswordResetConfirmView.as_view()(request, uidb64=matches.group(1), token=matches.group(2))
#     assert response.status_code == 200
#     assert response.data == {'password_reset_confirm_form': {'success_message': 'Password has been reset with the new password.'}}
#
#
# def test_password_reset_fail(api_rf):
#     request = api_rf.get('/pasword-reset-confirm')
#     response = PasswordResetConfirmView.as_view()(request, uidb64='INV', token='alid')
#     assert response.status_code == 200
#     assert response.data == {'validlink': False}
#     data = {
#         'form_data': {
#             'new_password1': 'secret1',
#             'new_password2': 'secret1',
#         }
#     }
#     request = api_rf.post('/pasword-reset-confirm', data, format='json')
#     response = PasswordResetConfirmView.as_view()(request, uidb64='INV', token='alid')
#     assert response.status_code == 422
#     assert response.data == {'password_reset_confirm_form': {'uid': ['Invalid value']}}
#
#
# @pytest.mark.django_db
# def test_register_user_with_password(api_client):
#     """
#     Test if a new user can register himself providing his own new password.
#     """
#     from testshop.models import Customer
#     register_user_url = reverse('shop:register-user')
#     data = {
#         'form_data': {
#             'email': 'newby@example.com',
#             'password1': 'secret',
#             'password2': 'secret',
#             'preset_password': False,
#         }
#     }
#     response = api_client.post(register_user_url, data, format='json')
#     assert response.status_code == 200
#     assert response.json() == {'register_user_form': {'success_message': 'Successfully registered yourself.'}}
#     customer = Customer.objects.get(user__email='newby@example.com')
#     assert customer is not None
#
#
# @pytest.mark.django_db
# def test_register_user_generate_password(settings, api_client):
#     """
#     Test if a new user can register himself and django-SHOP send a generated password by email.
#     """
#     settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
#     from testshop.models import Customer
#     register_user_url = reverse('shop:register-user')
#     data = {
#         'form_data': {
#             'email': 'newby@example.com',
#             'password1': '',
#             'password2': '',
#             'preset_password': True,
#         }
#     }
#     response = api_client.post(register_user_url, data, format='json')
#     assert response.status_code == 200
#     assert response.json() == {'register_user_form': {'success_message': 'Successfully registered yourself.'}}
#     customer = Customer.objects.get(user__email='newby@example.com')
#     assert customer is not None
#     body_begin = "You're receiving this e-mail because you or someone else has requested an auto-generated password"
#     assert len(mail.outbox) == 1
#     assert mail.outbox[0].body.startswith(body_begin)
#     matches = re.search('please use username newby@example.com with password ([0-9A-Za-z]+)', mail.outbox[0].body)
#     assert matches
#     password = matches.group(1)
#     assert api_client.login(username=customer.email, password=password) is True
#
#
# @pytest.mark.django_db
# def test_register_user_fail(registered_customer, api_client):
#     """
#     Test if a new user cannot register himself, if that user already exists.
#     """
#     register_user_url = reverse('shop:register-user')
#     data = {
#         'form_data': {
#             'email': registered_customer.email,
#             'password1': '',
#             'password2': '',
#             'preset_password': True,
#         }
#     }
#     response = api_client.post(register_user_url, data, format='json')
#     assert response.status_code == 422
#     assert response.json() == {
#         'register_user_form': {
#             '__all__': ["A customer with the e-mail address 'admin@example.com' already exists.\nIf you have used this address previously, try to reset the password."]
#         }
#     }
