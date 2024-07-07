from rest_framework.test import APITestCase
from django.urls import reverse
from rest_framework import status
from api.models import User, Organisation
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta
from django.utils import timezone
from django.test import Client, TestCase
import uuid
import bcrypt
class RegisterTests(APITestCase):
    def test_register_user_success(self):
        url = reverse('register')
        data = {
            "firstName": "test",
            "lastName": "user",
            "email": "user@example.com",
            "password": "testpassword",
            "phone": "07060806857"
        }
        response = self.client.post(url, data, format='json')
        Organisation.objects.create(name=f"{data.get('firstName')}'s organisation")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("data", response.data)
        self.assertEqual(response.data['data']['user']['firstName'], 'test')
        self.assertIn("test's organisation", Organisation.objects.get(users__firstName='test').name)


    def test_missing_required_fields(self):
        url = reverse('register')
        data = {
            "firstName": "",
            "lastName": "Doe",
            "email": "john.doe@example.com",
            "password": "p"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

    def test_duplicate_email(self):

        User.objects.create_user(userId=uuid.uuid4(), firstName='test', lastName='user', email='user@example.com', password='testpassword')
        url = reverse('register')
        data = {
            "firstName": "John",
            "lastName": "Doe",
            "email": "user@example.com",
            "password": "securepassword",
            "phone": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

class TokenTest(APITestCase):
    def test_token_expiry_and_correct_user(self):
        user = User.objects.create(userId=uuid.uuid4(), email='test@example', password='testpassword', firstName='test', lastName='user')
        refresh = RefreshToken.for_user(user)
        token = refresh.access_token.payload
        self.assertEqual(token['exp'], int((timezone.now() + timedelta(minutes=30)).timestamp()))
        self.assertEqual(token['user_id'],user.id)


class OrganisationTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(firstName='test', lastName='user', email='test@example.com',
                                             password='testpassword')
        self.org = Organisation.objects.create(name='Test Organisation')

    def test_user_cant_access_org_they_dont_belong(self):
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)

        url = reverse('specific-org', kwargs={'id': str(self.org.orgId)})
        response = self.client.get(url, HTTP_AUTHORIZATION='Bearer ' + access_token)
        self.assertEqual(response.status_code, 403)
