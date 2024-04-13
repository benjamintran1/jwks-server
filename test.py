import unittest
from http.client import HTTPConnection
import os
import sqlite3

class TestSuite(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.connection = HTTPConnection("localhost", 8080)
        cls.connection.connect()

        # Setup SQLite database connection
        cls.db_filename = "totally_not_my_privateKeys.db"
        cls.db_connection = sqlite3.connect(cls.db_filename)
    @classmethod
    def tearDownClass(cls):
        cls.connection.close()
        cls.db_connection.close()

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
        self.assertEqual(response.status, 201)

    # Check if database exists
    def test_database_exists(self):
        db_filename = "totally_not_my_privateKeys.db"
        self.assertTrue(os.path.exists(db_filename), f"Database file '{db_filename}' does not exist")
    
    def test_check_user_table(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        table_exists = cursor.fetchone()
        self.assertIsNotNone(table_exists, "The 'users' table does not exist")

    def test_check_key_table(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys';")
        table_exists = cursor.fetchone()
        self.assertIsNotNone(table_exists, "The 'keys' table does not exist")

    def test_check_auth_logs_table(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='auth_logs';")
        table_exists = cursor.fetchone()
        self.assertIsNotNone(table_exists, "The 'auth_logs' table does not exist")

if __name__ == "__main__":
    unittest.main()
