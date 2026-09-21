# AI Email Threat Detector

An AI-powered web application that analyzes emails and identifies potential security threats such as phishing, suspicious URLs, risky sender information, and suspicious keywords.

##  Features

-  Machine Learning based email threat detection
-  Suspicious keyword detection
-  URL security analysis
-  Sender and Reply-To analysis
- `.eml` file upload support
-  Risk score from 0–100
-  Low, Medium, and High Risk classification
-  Explanation of detected threats
-  Security recommendations
-  Privacy-first design

##  How It Works

The application analyzes an email using multiple detection methods:

1. **Machine Learning Analysis**
   - Uses TF-IDF text features
   - Uses Logistic Regression for classification

2. **Keyword Analysis**
   - Detects suspicious terms such as:
     - urgent
     - verify
     - password
     - OTP
     - account suspended
     - payment

3. **URL Analysis**
   - Detects HTTP URLs
   - Detects IP-based URLs
   - Detects shortened URLs
   - Detects suspicious URL terms
   - Detects potentially deceptive domains

4. **Sender Analysis**
   - Checks Sender and Reply-To domain mismatch
   - Detects temporary email domains
   - Checks suspicious sender-domain terms
   - Checks display-name and sender-domain mismatch

5. **Risk Calculation**
   - Combines the different analysis results
   - Produces a risk score between 0 and 100

##  Risk Levels

| Risk Score | Result |
|------------|--------|
| 0–29 | Low Risk |
| 30–59 | Medium Risk |
| 60–100 | High Risk |

##  Technologies Used

- Python
- Flask
- Scikit-learn
- HTML
- CSS
- JavaScript
- Git
- GitHub

##  Project Structure

```text
AI-Email-Threat-Detector/
│
├── app.py
├── requirements.txt
├── README.md
│
├── dataset/
│   └── emails.csv
│
├── model/
│   ├── model.pkl
│   ├── vectorizer.pkl
│   └── train_model.py
│
├── templates/
│   └── index.html
│
├── static/
│   └── style.css
│
├── utils/
│   ├── email_parser.py
│   └── url_analyzer.py
│
└── test_email.eml
