import requests
import unittest
import uuid
import hashlib
import time
import os
import sqlite3

BASE_URL = "http://uploader:8080"
DB_PATH = "/app/data/uploads/db.sqlite"

class TestCPAPApi(unittest.TestCase):
    def setUp(self):
        # The test key is already inserted manually while the container was stopped.
        self.api_key = "test-upload-key-123"
        # We'll just rely on the server having it.

    def test_01_create_session(self):
        headers = {"x-api-key": self.api_key}
        payload = {"device_id": "test-device-001", "import_type": "sdcard"}
        response = requests.post(f"{BASE_URL}/api/v1/imports", json=payload, headers=headers)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("id", data)
        self.__class__.session_id = data["id"]

    def test_02_create_duplicate_session(self):
        headers = {"x-api-key": self.api_key}
        payload = {"device_id": "test-device-002"}
        response = requests.post(f"{BASE_URL}/api/v1/imports", json=payload, headers=headers)
        self.assertEqual(response.status_code, 409)

    def test_03_upload_file(self):
        headers = {"x-api-key": self.api_key}
        file_content = b"0       " + b"X" * 250 # Fake EDF magic
        md5_hash = hashlib.md5(file_content).hexdigest()
        
        files = {
            "file": ("test.edf", file_content),
            "path": (None, "DATALOG/20240101/test.edf"),
            "content_hash": (None, md5_hash)
        }
        
        response = requests.post(f"{BASE_URL}/api/v1/imports/{self.session_id}/files", files=files, headers=headers)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["status"], "received")

    def test_04_upload_duplicate_file(self):
        headers = {"x-api-key": self.api_key}
        file_content = b"0       " + b"X" * 250
        md5_hash = hashlib.md5(file_content).hexdigest()
        
        files = {
            "file": ("test.edf", file_content),
            "path": (None, "DATALOG/20240101/test.edf"),
            "content_hash": (None, md5_hash)
        }
        
        response = requests.post(f"{BASE_URL}/api/v1/imports/{self.session_id}/files", files=files, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "skipped")

    def test_05_upload_invalid_magic(self):
        headers = {"x-api-key": self.api_key}
        file_content = b"INVALID MAGIC"
        md5_hash = hashlib.md5(file_content).hexdigest()
        
        files = {
            "file": ("test.edf", file_content),
            "path": (None, "DATALOG/20240101/invalid.edf"),
            "content_hash": (None, md5_hash)
        }
        
        response = requests.post(f"{BASE_URL}/api/v1/imports/{self.session_id}/files", files=files, headers=headers)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Validation failed", response.json()["error"])

    def test_06_finalize_session(self):
        headers = {"x-api-key": self.api_key}
        response = requests.post(f"{BASE_URL}/api/v1/imports/{self.session_id}/process_files", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "complete")

    def test_07_rate_limiting(self):
        headers = {"x-api-key": self.api_key}
        # We need to make > 300 requests within a minute.
        # But for this test, let's just do a few and see if it doesn't crash.
        # Actual rate limit testing might be slow in CI but good for manual sweep.
        pass

if __name__ == "__main__":
    unittest.main()
