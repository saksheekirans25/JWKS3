import unittest
from main import create_app
import json
from unittest.mock import patch
import uuid

class AppTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def test_register_user_success(self):
        data = {
            "username": "testuser",
            "email": "testuser@example.com"
        }
        response = self.client.post('/register', json=data)
        self.assertEqual(response.status_code, 201)
        self.assertIn("password", response.json)  # Ensure password is returned

    def test_register_user_missing_username(self):
        data = {
            "email": "testuser@example.com"
        }
        response = self.client.post('/register', json=data)
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json)

    def test_store_private_key_success(self):
        data = {
            "private_key": "myprivatekey"
        }
        response = self.client.post('/store_private_key', json=data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("message", response.json)

    def test_store_private_key_missing_key(self):
        data = {}
        response = self.client.post('/store_private_key', json=data)
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json)

    def test_get_private_key_success(self):
        # Store a test key first
        data = {
            "private_key": "myprivatekey"
        }
        self.client.post('/store_private_key', json=data)

        response = self.client.get('/get_private_key')
        self.assertEqual(response.status_code, 200)
        self.assertIn("private_key", response.json)

    def test_get_private_key_not_found(self):
        response = self.client.get('/get_private_key')
        self.assertEqual(response.status_code, 404)
        self.assertIn("error", response.json)

    def test_jwks_success(self):
        response = self.client.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        self.assertIn("keys", response.json)

    def test_auth_success(self):
        # Register a user and use that user for authentication
        username = "testuser"
        password = str(uuid.uuid4())  # use a random password
        data = {
            "username": username,
            "email": "testuser@example.com"
        }
        register_response = self.client.post('/register', json=data)
        self.assertEqual(register_response.status_code, 201)
        # Fix: Ensure a password field is in the response
        password_hash = register_response.json.get('password')
        self.assertIsNotNone(password_hash, "Password should be returned in the response")

        auth_data = {
            "username": username,
            "password": password_hash
        }

        response = self.client.post('/auth', json=auth_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("message", response.json)

    def test_auth_invalid_credentials(self):
        data = {
            "username": "invaliduser",
            "password": "wrongpassword"
        }
        response = self.client.post('/auth', json=data)
        self.assertEqual(response.status_code, 401)
        self.assertIn("message", response.json)

    def test_auth_missing_credentials(self):
        data = {
            "username": "testuser"
        }
        response = self.client.post('/auth', json=data)
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json)

    def test_rate_limit_exceeded(self):
        # Rate limiting test, assuming it's set to 10 per second
        data = {
            "username": "testuser",
            "password": "password"
        }
        for _ in range(11):
            response = self.client.post('/auth', json=data)
        self.assertEqual(response.status_code, 429)

if __name__ == '__main__':
    unittest.main()
