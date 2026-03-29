import argparse
import os
import hashlib
import requests
import sys

# --- CONFIGURATION ---
DEFAULT_API_KEY = "YOUR_API_KEY_HERE"
DEFAULT_BASE_URL = "https://test.sdbfriends.ca"
# ---------------------

def get_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def upload_recursive(root_dir, api_key, base_url, import_type):
    headers = {"x-api-key": api_key}
    script_name = os.path.basename(__file__)
    
    # 1. Create Session
    print(f"[*] Creating {import_type} sync session at {base_url}...")
    try:
        resp = requests.post(
            f"{base_url}/api/v1/imports",
            json={"device_id": "manual-recursive-test", "import_type": import_type},
            headers=headers
        )
        if resp.status_code != 201:
            print(f"[!] Failed to create session: {resp.status_code} - {resp.text}")
            return
        
        session_id = resp.json().get("id")
        print(f"[+] Session created: {session_id}")
    except Exception as e:
        print(f"[!] Connection error during session creation: {e}")
        return

    files_uploaded = 0
    files_skipped = 0
    errors = 0

    # 2. Walk and Upload
    print(f"[*] Scanning directory: {root_dir}")
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file == script_name:
                continue
            
            file_path = os.path.join(root, file)
            # Relative path for the server
            rel_path = os.path.relpath(file_path, root_dir).replace('\\', '/')
            
            # Simple progress display
            sys.stdout.write(f"\r[*] Processing: {rel_path[:50]:<50}")
            sys.stdout.flush()
            
            try:
                content_hash = get_md5(file_path)
                with open(file_path, "rb") as f:
                    upload_files = {
                        "file": (file, f),
                        "path": (None, rel_path),
                        "content_hash": (None, content_hash)
                    }
                    u_resp = requests.post(
                        f"{base_url}/api/v1/imports/{session_id}/files",
                        files=upload_files,
                        headers=headers
                    )
                
                if u_resp.status_code in [200, 201]:
                    status = u_resp.json().get("status")
                    if status == "skipped":
                        files_skipped += 1
                    else:
                        files_uploaded += 1
                else:
                    errors += 1
                    print(f"\n[!] Error uploading {rel_path}: {u_resp.status_code} - {u_resp.text}")
                    
            except Exception as e:
                errors += 1
                print(f"\n[!] Exception during upload of {rel_path}: {e}")

    print(f"\n[+] Scan complete. Uploaded: {files_uploaded}, Skipped: {files_skipped}, Errors: {errors}")

    # 3. Finalize Session
    print(f"[*] Finalizing session {session_id}...")
    try:
        f_resp = requests.post(
            f"{base_url}/api/v1/imports/{session_id}/process_files",
            headers=headers
        )
        if f_resp.status_code == 200:
            print("[+] Session finalized successfully. Container refresh triggered.")
        else:
            print(f"[!] Failed to finalize session: {f_resp.status_code} - {f_resp.text}")
    except Exception as e:
        print(f"[!] Connection error during finalization: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursive CPAP/Oximetry Uploader")
    parser.add_argument("--key", help="API Key (overrides script default)")
    parser.add_argument("--oximetry", action="store_true", help="Flag as oximetry data")
    parser.add_argument("--url", help="Base URL (overrides script default)")
    args = parser.parse_args()

    api_key = args.key or DEFAULT_API_KEY
    base_url = args.url or DEFAULT_BASE_URL
    import_type = "oximetry" if args.oximetry else "sdcard"

    if api_key == "YOUR_API_KEY_HERE":
        print("[!] Please set your API_KEY in the script or use --key")
        sys.exit(1)
        
    start_dir = os.getcwd()
    upload_recursive(start_dir, api_key, base_url, import_type)
