import unittest
from flask import json
from jwks import app, key_pairs

class TestSuite(unittest.TestCase):

    def setUp(self):
        app.testing = True
        self.app = app.test_client()

    def test_jwks_endpoint(self):
        response = self.app.get('/jwks')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('keys', data)

    def test_authenticate_endpoint_with_expired_key(self):
        # Add a dummy key to key_pairs
        key_pairs['dummy_key'] = {
            'private_key': b'private_key',
            'public_key': b'public_key',
            'expiration': datetime.utcnow() - timedelta(minutes=1)
        }
        response = self.app.post('/auth?expired=dummy_key')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('Invalid key ID', data['error'])

    def test_authenticate_endpoint_without_expired_key(self):
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)

    def tearDown(self):
        # Clean up key_pairs after each test
        key_pairs.clear()

if __name__ == '__main__':
    unittest.main()
