# Privacy and Security Policy

This application was designed with user privacy and security as a top priority. Below is an overview of our data handling practices and security posture.

---

## 🔒 Data Privacy

### 1. Data Collection & Retention
Aside from the data you choose to explicitly submit to the service, **no data is collected, stored, or retained**. 
*   **No Third-Party Distribution**: No data is ever distributed or sold to any third parties. 
*   **No IP Logging**: No IP addresses are ever collected or retained. 
*   **Data Removal**: If you wish to remove previously uploaded data at any time, please use the delete function provided within the service UI, or reach out to your system administrator.

### 2. Personally Identifiable Information (PII)
**Your SD card data does not contain personally identifiable information.** 
*   The only unique identifier in your SD Card data is your CPAP machine’s serial number. 
*   Your OSCAR profile is created automatically for you with bare minimum information (your username). 
*   **Recommendation**: Do not input any extra information to your profile (such as your real name or address) that you do not wish to share.

---

## 🛡️ Application Security

### 1. Transit Encryption (SSL/TLS)
This service is delivered through Secure Tunneling (e.g., Cloudflare). 
*   **Encryption in Transit**: All data transmitted to and from the service is protected using SSL/TLS encryption. 
*   **Tinfoil Hat Mode**: If you are concerned about TLS termination at the edge (e.g., Cloudflare), you may enable **"Tinfoil Hat Mode"**. This ensures your data is encrypted client-side in your browser and is never fully unencrypted until it reaches this sharing service.

### 2. Safeguards & Hardening
OSCAR Shareable was built with a strong emphasis on application security. Multiple safeguards and hardening measures (including per-user container isolation and secure API key hashing) have been implemented to reduce risk. 

> [!WARNING]
> **No Absolute Guarantees**
> While we have taken extensive measures to secure this application, no web application can be guaranteed to be completely secure against all possible threats.

---

## 🤖 Responsible Use & AI Statement

*   **Generative AI**: Portions of this software were created using generative AI and therefore could be subject to unexpected behavior. Thorough efforts have been undertaken to ensure everything is working as designed.
*   **User Agreement**: By using this service, you agree to use it responsibly and not upload any content that is illegal, harmful, or inappropriate.
