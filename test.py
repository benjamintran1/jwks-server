import unittest
from flask import json
from jwks import app, key_pairs, generate_key_pair
from datetime import datetime, timedelta

class TestSuite(unittest.TestCase):

    def setUp(self):
        app.testing = True
        self.app = app.test_client()
    # checks GET request
    def test_jwks_endpoint(self):
        response = self.app.get('/jwks')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('keys', data)
        
    # Use expired key for POST
    def test_authenticate_endpoint_with_expired_key(self):
        # Add dummy key to key_pairs
        key_pairs['1'] = {
            'private_key': b'private_key',
            'public_key': b'public_key',
            'expiration': int((datetime.utcnow() + timedelta(minutes=1)).timestamp())
        }
        response = self.app.post('/auth?expired=fake_key')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('Invalid key ID', data['error'])
        
    # Use non-expired key for POST
    def test_authenticate_endpoint_without_expired_key(self):
        generate_key_pair('1')
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)

    # POST with no available keys
    def test_authenticate_endpoint_with_no_valid_keys(self):
        # Clear all existing keys
        key_pairs.clear()
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('No valid keys available', data['error'])

    # Generate token
    def test_jwt_token_creation(self):
        # Add a valid key to key_pairs
        key_pairs['1'] = {
            'private_key': b'private_key',
            'public_key': b'public_key',
            'expiration': int((datetime.utcnow() + timedelta(minutes=1)).timestamp())
        }
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)

    def tearDown(self):
        # clear key_pairs after each test 
        key_pairs.clear()

if __name__ == '__main__':
    unittest.main()
