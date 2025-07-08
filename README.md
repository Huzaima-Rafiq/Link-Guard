# Link Guard

**Link Guard** is a real-time URL analysis tool built with Python and Streamlit. It performs multi-layered security checks on web links to help users detect and evaluate potential threats. It is designed for researchers, analysts, and everyday users who need fast, comprehensive URL safety assessments.

---

## **Features**

* **URL Validation**
  Ensures the URL is syntactically correct and adheres to standard formats.

* **Accessibility Check**
  Verifies whether the URL is reachable and returns a valid response.

* **SSL Certificate Analysis**
  Inspects the site's SSL certificate for validity, expiration, and trust chain verification.

* **Domain Reputation**
  Checks the domain against known blacklists and evaluates its historical trustworthiness.

* **Content Analysis**
  Reviews the website content for suspicious elements or known malicious patterns.

* **Risk Assessment**
  Uses multiple data points to determine the potential risk associated with the URL.

* **Redirect Detection**
  Identifies and maps any redirects from the original URL to detect phishing or masking attempts.

---

## **Core Capabilities**

### **Comprehensive URL Analysis**

Link Guard performs a full security audit of URLs, combining multiple layers of analysis such as SSL checks, domain reputation lookup, and content inspection to identify threats.

### **Real-time Scanning**

Powered by a fast scanning engine, Link Guard delivers immediate results by checking URLs against multiple security parameters.

### **Risk Scoring**

Our intelligent risk scoring algorithm evaluates the findings of each scan to provide a clear and concise indication of URL safety.

### **Detailed Reports**

Each scan generates a comprehensive, exportable report in JSON format. These reports are suitable for documentation, compliance, or advanced threat analysis.

---

## **File Structure**

```
link-guard/
├── app.py                   # Main Streamlit application
├── userrequirements.txt     # Python dependencies
├── README.md                # Project documentation
└── sample-urls.txt          # Optional: Sample testing URLs
```

---

## **How to Run the App**

1. **Install Dependencies**
   Run the following command to install required libraries:

   ```bash
   pip install -r userrequirements.txt
   ```

2. **Launch the Streamlit App**
   Use the following command to start the application:

   ```bash
   streamlit run app.py
   ```

3. **Scan URLs**
   Paste any URL into the interface and view detailed real-time results.

---

## **License**

This project is released under the MIT License.

---
