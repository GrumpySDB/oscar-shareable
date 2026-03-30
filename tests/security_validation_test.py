import requests
import os
import hashlib
import sys

# --- CONFIGURATION ---
API_KEY = "YOUR_API_KEY_HERE"
BASE_URL = "https://test.sdbfriends.ca"
# ---------------------

def run_security_tests():
    headers = {"x-api-key": API_KEY}
    
    # Create a session for testing
    print("[*] Creating test session...")
    resp = requests.post(f"{BASE_URL}/api/v1/imports", 
                         json={"device_id": "security-test", "import_type": "sdcard"}, 
                         headers=headers)
    if resp.status_code != 201:
        print(f"[!] Failed to create session: {resp.status_code}")
        return
    session_id = resp.json().get("data", {}).get("id")
    print(f"[+] Session: {session_id}")

    def test_upload(name, filename, path, content, expected_status=400):
        print(f"[*] Testing {name}...", end=" ")
        files = {
            "file": (filename, content),
            "path": (None, path),
            "content_hash": (None, hashlib.md5(content).hexdigest())
        }
        res = requests.post(f"{BASE_URL}/api/v1/imports/{session_id}/files", files=files, headers=headers)
        if res.status_code == expected_status:
            print(f"PASSED (Received {res.status_code})")
        else:
            print(f"FAILED (Expected {expected_status}, got {res.status_code})")
            print(f"    Detail: {res.text}")

    # 1. Invalid Extension
    test_upload("Invalid Extension (.exe)", "malware.exe", "malware.exe", b"MZtestcontent")

    # 2. Correct Extension, Invalid Magic Bytes
    test_upload("Invalid Magic Bytes (.edf)", "fake.edf", "fake.edf", b"This is not an EDF file")

    # 3. Oversized CPAP File (Limit 10MB)
    oversized_cpap = b"A" * (11 * 1024 * 1024)
    test_upload("Oversized CPAP (>10MB)", "big.edf", "big.edf", oversized_cpap)

    # 4. Oversized Oximetry File (Limit 200KB)
    # Note: We need to create an oximetry session or the API will check against CPAP limits?
    # Actually, the file limits are per extension in validation.rs. .spo2 is 200KB.
    oversized_ox = b"X\x03" + (b"A" * 300 * 1024)
    test_upload("Oversized Oximetry (>200KB)", "big.spo2", "big.spo2", oversized_ox)

    # 5. Empty File
    test_upload("Empty File", "empty.edf", "empty.edf", b"")

    # 6. Path Traversal Attempt
    test_upload("Path Traversal (..)", "test.edf", "../../../test.edf", b"0testcontent", expected_status=400)

    print("\n[*] Validation tests complete.")

if __name__ == "__main__":
    if API_KEY == "YOUR_API_KEY_HERE":
        print("[!] Please set your API_KEY in the script.")
        sys.exit(1)
    run_security_tests()
