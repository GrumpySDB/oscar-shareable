# Third-Party Upload API Specification

The OSCAR Shareable API allows third-party hardware (like the ESP32-based **CPAP-AutoSync**) and custom clients to securely synchronize CPAP data without using the browser UI. 

This API follows a **Session-based Import Workflow** to ensure data integrity and atomicity when updating the OSCAR environment.

## 🔐 Authentication

All requests to the API must include the following HTTP Header:

`x-api-key: <YOUR_API_KEY>`

You can generate and manage your API keys in the **Account Settings > API Keys** section of the OSCAR Shareable dashboard.

---

## 📅 Session Workflow

To perform a synchronization, a client MUST follow this sequence:

1.  **Create an Import Session**: Obtain a session ID.
2.  **Upload Files**: Send files one at a time (multi-part).
3.  **Process Session**: Signal the server to finalize the sync and refresh the OSCAR container.

### 1. Create Import Session
**POST** `/api/v1/imports`

**Request Body (JSON):**
```json
{
  "device_id": "esp32-abc1234",
  "import_type": "sdcard" 
}
```
*Note: `import_type` defaults to "sdcard" if omitted.*

| Response Code | Description |
| :--- | :--- |
| **201 Created** | Session created successfully. Returns the session ID. |
| **401 Unauthorized** | Missing or invalid API key. |
| **500 Internal Error** | Database or system failure. |

**Example Response:**
```json
{
  "data": {
    "id": 123,
    "type": "imports",
    "attributes": {
      "id": 123,
      "status": "active"
    }
  }
}
```

---

### 2. Upload File
**POST** `/api/v1/imports/{id}/files`

This endpoint accepts a single file via `multipart/form-data`.

**Multipart Fields:**
- `path`: (Required) Relative directory path within the SD card (e.g., `DATALOG/20230924`).
- `content_hash`: (Required) MD5 hash of `(file_content + original_filename)`. Used for integrity and deduplication.
- `file`: (Required) The binary payload of the file.

| Response Code | Description |
| :--- | :--- |
| **201 Created** | File received and verified. |
| **400 Bad Request** | Missing fields, invalid path, or MD5 mismatch. |
| **413 Payload Too Large** | File exceeds the 10MB individual limit. |

**Example Response:**
```json
{
  "status": "received"
}
```

---

### 3. Commit/Process Session
**POST** `/api/v1/imports/{id}/process_files`

Finalizes the session, updates the user's `Profile.xml` to point to the new data, and triggers an eviction of the current OSCAR container so the next launch uses the fresh data.

| Response Code | Description |
| :--- | :--- |
| **200 OK** | Session completed and container refresh triggered. |
| **403 Forbidden** | Attempted to process a session not owned by the API key user. |

**Example Response:**
```json
{
  "status": "complete"
}
```

---

## 🛡️ Integrity Verification (MD5 Strategy)

To ensure that files are not corrupted during upload, OSCAR Shareable calculates a custom MD5 hash.

**Algorithm**: `MD5(binary_content + original_filename_string)`

Clients should calculate this on the device before transmission and provide it in the `content_hash` field. The server will reject the upload if the hashes do not match.

## 💻 Example Usage (curl)

**1. Create Session**
```bash
curl -X POST https://app.example.com/api/v1/imports \
     -H "x-api-key: MY_SECRET_KEY" \
     -H "Content-Type: application/json" \
     -d '{"device_id": "laptop-01"}'
```

**2. Upload a File**
```bash
curl -X POST https://app.example.com/api/v1/imports/123/files \
     -H "x-api-key: MY_SECRET_KEY" \
     -F "path=DATALOG/20231027" \
     -F "content_hash=595f44fec1e92a71d3e9e77456db0d06" \
     -F "file=@/path/to/STR.edf"
```

**3. Finalize**
```bash
curl -X POST https://app.example.com/api/v1/imports/123/process_files \
     -H "x-api-key: MY_SECRET_KEY"
```
