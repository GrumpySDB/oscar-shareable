# Pull Request Design: SDBFriends API Support for CPAP-AutoSync

## Objective
To provide a simple, minimalist, and highly maintainable Pull Request (PR) to the CPAP-AutoSync project that enables users to upload their CPAP data to SDBFriends (app.sdbfriends.ca) without duplicating massive amounts of TLS-heavy upload code.

## Architectural Approach
Instead of creating a brand new isolated `SDBFriendsUploader` class (which would require duplicating ~1400 lines of complex, finely-tuned, memory-managed streaming TLS networking code from `SleepHQUploader.cpp`), we will implement a minimalist **"API Key Mode"** toggle within the existing `SleepHQUploader`.

Because the SDBFriends API was deliberately designed to mirror the SleepHQ ingestion REST structure (`/api/v1/imports`), the only functional difference is the authentication mechanism: SleepHQ uses an OAuth2 password flow resulting in a Bearer token, whereas SDBFriends uses a static `x-api-key` header.

By allowing users to input an API Key and a custom Cloud URL in the Web Portal, the `SleepHQUploader` can seamlessly switch to the SDBFriends API, bypassing OAuth and seamlessly streaming files precisely as it does today.

---

## Required Code Changes

### 1. Identify "SDBFriends" Mode
We do **not** need to modify the configuration management (`Config.h`, `Config.cpp`, `WebPortal.cpp`). Instead, we leverage the existing fields:
- Users input `sdbfriends` into the **Client ID** field.
- Users input their API Key into the **Client Secret** field.

### 2. Bypassing OAuth (`src/SleepHQUploader.cpp`)

If the `clientId` equals `sdbfriends`, the firmware does not need to hit `/oauth/token` or discover a `team_id`. 

- **`ensureAccessToken()`**:
  ```cpp
  bool SleepHQUploader::ensureAccessToken() {
      if (config->getCloudClientId().equalsIgnoreCase("sdbfriends")) {
          // Bypass OAuth when using SDBFriends API Key
          accessToken = config->getCloudSecret(); // The API Key is stored in the secret field
          tokenExpiresAt = millis() + (86400 * 1000); // effectively infinite for this session
          return true;
      }
      // ... existing OAuth logic ...
  }
  ```

- **`discoverTeamId()`**:
  ```cpp
  bool SleepHQUploader::discoverTeamId() {
      if (config->getCloudClientId().equalsIgnoreCase("sdbfriends")) {
          // SDBFriends does not use Team IDs for routing
          teamId = "api"; 
          return true; 
      }
      // ... existing /api/v1/me logic ...
  }
  ```

### 3. Header Injection & Path Routing (`src/SleepHQUploader.cpp`)

Modify the core network functions to inject the `x-api-key` header instead of `Authorization: Bearer` when in SDBFriends mode.

- **`createImport()`**:
  ```cpp
  bool SleepHQUploader::createImport() {
      // ... ensure token ...
      String path;
      if (config->getCloudClientId().equalsIgnoreCase("sdbfriends")) {
          path = "/api/v1/imports"; // SDBFriends route
      } else {
          path = "/api/v1/teams/" + teamId + "/imports"; // SleepHQ route
      }
      // ...
  }
  ```

- **`httpRequest()`**:
  Around line 655 where headers are built:
  ```cpp
  if (config->getCloudClientId().equalsIgnoreCase("sdbfriends")) {
      n = snprintf(hdrBuf, sizeof(hdrBuf), "x-api-key: %s\r\n", accessToken.c_str());
  } else {
      n = snprintf(hdrBuf, sizeof(hdrBuf), "Authorization: Bearer %s\r\n", accessToken.c_str());
  }
  ```

- **`httpMultipartUpload()`**:
  Around line 982 where multipart headers are built:
  ```cpp
  if (config->getCloudClientId().equalsIgnoreCase("sdbfriends")) {
      n = snprintf(hdrBuf, sizeof(hdrBuf), "x-api-key: %s\r\n", accessToken.c_str());
  } else {
      n = snprintf(hdrBuf, sizeof(hdrBuf), "Authorization: Bearer %s\r\n", accessToken.c_str());
  }
  ```

## Why this PR is Optimal
1. **Zero UI Changes**: Users just type `sdbfriends` into the existing Cloud portal. The ESP32's frontend code remains completely untouched.
2. **Minimalist**: This PR touches exactly ~10 lines of core logic rather than introducing thousands of lines of duplicated, untested code.
3. **Robust**: By reusing `SleepHQUploader.cpp`, the SDBFriends upload immediately inherits the battle-tested resilient networking code authored for SleepHQ.
