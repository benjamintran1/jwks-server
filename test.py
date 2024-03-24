import unittest
from http.client import HTTPConnection
import json
import jwt
import time
import os

class TestSuite(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.connection = HTTPConnection("localhost", 8080)
        cls.connection.connect()

    @classmethod
    def tearDownClass(cls):
        cls.connection.close()

    # check if PUT fails properly
    def test_PUT(self):
        self.connection.request("PUT", "/auth")
        response = self.connection.getresponse()
        self.assertEqual(response.status, 405)

    # check if PATCH fails properly
    def test_PATCH(self):
        self.connection.request("PATCH", "/auth")
        response = self.connection.getresponse()
        self.assertEqual(response.status, 405)    

    # check if DELETE fails properly
    def test_DELETE(self):
        self.connection.request("DELETE", "/auth")
        response = self.connection.getresponse()
        self.assertEqual(response.status, 405)

    # check if HEAD fails properly 
    def test_HEAD(self):
        self.connection.request("HEAD", "/auth")
        response = self.connection.getresponse()
        self.assertEqual(response.status, 405)

    # check if POST works
    def test_POST(self):
        self.connection.request("POST", "/auth")
        response = self.connection.getresponse()
        self.assertEqual(response.status, 200)

    # Check if database exists
    def test_database_exists(self):
        db_filename = "totally_not_my_privateKeys.db"
        self.assertTrue(os.path.exists(db_filename), f"Database file '{db_filename}' does not exist")
        

if __name__ == "__main__":
    unittest.main()
