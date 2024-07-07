from rest_framework.test import APITestCase
from django.urls import reverse
from rest_framework import status
from api.models import User, Organisation
import uuid

class AuthTests(APITestCase):
    def test_register_user_success(self):
        url = reverse('register')
        data = {
            "firstName":"test",
            "lastName":"user",
            "email":"user@example.com",
            "password":"Password",
            "phone":"07060806857"
        }
        response = self.client.post(url, data, format='json')
        Organisation.objects.create(name=f"{data.get('firstName')}'s organisation")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("data", response.data)
        self.assertEqual(response.data['data']['user']['firstName'], 'test')
        self.assertIn("test's Organisation", Organisation.objects.get(users__firstName='test').name)

    def test_login_user_success(self):
        user = User.objects.create_user(userId=uuid.uuid4(), firstName='test', lastName='user', email='user@example.com', password='testpassword')
        url = reverse('login')
        data = {
            'email':'user@example.com',
            'password':'testpassword'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("data", response.data)
        self.assertEqual(response.data['data']['user']['email'], 'user@example.com')

    def test_missing_required_fields(self):
        url = reverse('register')
        data = {
            "firstName": "",
            "lastName": "Doe",
            "email": "john.doe@example.com",
            "password": "password123"
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
            "password": "password123",
            "phone": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)