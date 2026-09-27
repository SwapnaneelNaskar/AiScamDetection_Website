# AI Scam Detector for Messages & Websites
> **Real-Time AI Threat Intelligence & Machine Learning Protection**

An AI-powered cybersecurity application that analyzes suspicious messages, website URLs, and screenshots to identify potential scam or phishing indicators. Instead of only displaying *'Scam'* or *'Not Scam'*, the system provides an interpretable risk assessment (0–100), detected warning signs with textual evidence, scam categorization, technical URL analysis, and actionable safety recommendations.

---

## 🌟 Key Features

1. **Multi-Signal Risk Assessment**:
   - Fuses **Machine Learning Probability (40%)**, **Explainable NLP Rules (35%)**, and **Technical URL Inspection (25%)** into a calibrated 0–100 Risk Score.
   - Assigns Risk Levels: `LOW` (0–34), `MEDIUM` (35–64), `HIGH` (65–84), and `CRITICAL` (85–100).

2. **AI & Machine Learning (scikit-learn)**:
   - Evaluates and benchmarks 4 algorithms:
     - **Multinomial Naive Bayes** (Accuracy: 97.37%, F1: 97.92%)
     - **Logistic Regression** (Accuracy: 98.68%, F1: 98.97%) — *Active Production Model*
     - **Linear SVM** (Accuracy: 98.68%, F1: 98.97%)
     - **Random Forest** (Accuracy: 97.37%, F1: 97.96%)
   - Trained on a balanced corpus across SMS, emails, bank notifications, job scams, prize frauds, and genuine OTPs.

3. **Explainable NLP & Social Engineering Heuristics**:
   - Detects artificial urgency (*"URGENT"*, *"WITHIN 24 HOURS"*).
   - Detects coercive threats (*"Account suspended"*, *"Police arrest warrant"*).
   - Detects sensitive credential harvesting (*"Enter OTP"*, *"NetBanking password"*).
   - Detects advance payment demands (*"Processing fee"*, *"Clearance tax"*).
   - Context-aware negation filter (*"Do not share OTP"* is recognized as legitimate advice).

4. **Deep Technical URL Inspector**:
   - Protocol check (flags unencrypted HTTP, notes free SSL caveats on HTTPS).
   - Numeric IP address detection (e.g. `http://192.168.1.1/...`).
   - Domain Shannon entropy calculation (identifies randomized DGA domains).
   - Suspicious TLD detection (`.xyz`, `.top`, `.icu`, `.buzz`, `.cc`, etc.).
   - URL shortener identification (`bit.ly`, `tinyurl`, `is.gd`).
   - Brand typosquatting and impersonation heuristics.

5. **Client-Side Screenshot OCR (Tesseract.js WebAssembly)**:
   - Upload any screenshot (SMS, WhatsApp, email) to extract text directly in the browser with 0 external C++ binaries required.
   - Visual progress bar and editable extracted text box.

6. **SQLite Persistence & Analytics Dashboard**:
   - Stores complete scan history with timestamps, snippets, risk levels, and categories.
   - 1-click **Export to CSV** for reports.

7. **Academic Viva Voce & Presentation Mode**:
   - Built-in modal presenting live scikit-learn metrics, confusion matrix, Chart.js visual graph, and answers to viva examination questions (matching Section 18 of the CSE specification).

---

## 🚀 How to Open and Run in VS Code

### Method 1: The Quickest Way (One-Click)
1. Open **VS Code**.
2. Go to **File -> Open Folder...** and select this directory on your Desktop:
   ```
   C:\Users\LENOVO\Desktop\ai_scam_detector
   ```
3. Open a terminal in VS Code (`Ctrl + ~` or **Terminal -> New Terminal**) and run:
   ```powershell
   .\run.bat
   ```
   *or:*
   ```powershell
   .\run.ps1
   ```
4. The server will start and automatically open `http://127.0.0.1:8000` in your web browser!

---

### Method 2: Running via VS Code "Go Live" (Live Server Extension)
If you prefer running via VS Code's **Go Live** extension:
1. Right-click `frontend/index.html` in VS Code file explorer -> click **Open with Live Server**.
2. The dashboard will open on `http://127.0.0.1:5500`.
3. The dashboard features an **automatic client-side AI analysis engine**, so all scans, threat presets, and screenshot OCR work seamlessly without throwing errors!
4. **Interactive Swagger UI**:
   - Click the **API Docs** button in the header -> Click **Open Full Swagger UI** (or navigate to `http://127.0.0.1:5500/docs.html`).
   - The full interactive Swagger UI OpenAPI 3.1 explorer will open instantly in your browser!
5. To enable live backend API requests, simply run `.\run.bat` in your VS Code terminal.

---

### Method 3: Running via VS Code Run / Debug (F5)
1. Open the project folder in VS Code.
2. Ensure the Python extension in VS Code is active:
   - Press `Ctrl + Shift + P` -> Type **Python: Select Interpreter**.
   - Choose: `.\.venv\Scripts\python.exe`.
3. Press **F5** (or click **Run -> Start Debugging** from the top menu).
4. Select configuration: **"Run AI Scam Detector (Web App)"**.
5. Open your browser and navigate to: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**.

---

### Method 3: Running from VS Code Integrated Terminal
```powershell
# 1. Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# 2. Run the application with Uvicorn
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 📂 Project Architecture

```
ai_scam_detector/
├── .vscode/
│   ├── launch.json              # VS Code F5 Run/Debug configurations
│   └── settings.json            # VS Code Python environment paths
├── .venv/                       # Isolated Python 3.12 Virtual Environment
├── requirements.txt             # Freezed dependencies (fastapi, scikit-learn, etc.)
├── main.py                      # FastAPI server & REST API endpoints
├── train_model.py               # Standalone ML training & benchmark script
├── run.bat                      # 1-click Windows batch launcher
├── run.ps1                      # PowerShell launcher
├── README.md                    # Project documentation & viva guide
├── backend/
│   ├── __init__.py
│   ├── schemas.py               # Pydantic data contracts
│   ├── database.py              # SQLite storage & history queries
│   ├── sample_dataset.py        # Curated dataset of scam & legitimate messages
│   ├── classifier.py            # TF-IDF vectorizer & 4 benchmarked classifiers
│   ├── rule_engine.py           # Explainable NLP heuristic indicators
│   ├── url_analyzer.py          # Structural URL inspection & entropy engine
│   └── risk_engine.py           # Multi-signal weighted risk score fusion
├── models/
│   ├── scam_model.joblib        # Serialized ML pipeline bundle
│   └── model_metrics.json       # Benchmarked evaluation scores & confusion matrix
├── frontend/
│   ├── index.html               # Modern cyber-defense dashboard
│   ├── css/
│   │   └── styles.css           # Glassmorphism, animations, gauges
│   └── js/
│       ├── app.js               # Application state, presets, API communication
│       └── ocr.js               # Tesseract.js WebAssembly client OCR engine
└── tests/
    └── test_api.py              # Automated test suite
```

---

## 🧪 Testing the Presets

In the web interface on the left-hand panel, click the **"Viva Demonstration Presets"** buttons to test immediate real-world cases:

| Preset Name | Threat Type | Expected Risk Level | Indicators Flagged |
| :--- | :--- | :--- | :--- |
| **Prize Scam (KBC / Lucky Draw)** | Lottery / Advance Fee | `HIGH / CRITICAL` (85/100) | Unsolicited prize claim, Advance fee, Urgency |
| **Bank KYC Phishing** | Credential Harvesting | `CRITICAL` (88/100) | Urgency, Account suspension threat, Suspicious TLD |
| **FedEx Delivery Scam** | Courier / Customs Fee | `HIGH` (70–80/100) | Package held, Redelivery charge, Suspicious domain |
| **Telegram Job Scam** | Fake Task / Rating | `HIGH` (70–75/100) | Unrealistic daily pay, Telegram task recruiter |
| **Electricity Disconnection** | Coercive Extortion | `HIGH` (70–78/100) | Power cutoff threat, Immediate payment pressure |
| **Legitimate Bank OTP** | Authentic Authentication | `LOW` (20–25/100) | Standard notification, "Do not share" advice detected |
| **Authentic Bank Debit Alert** | Transactional SMS | `LOW` (10–15/100) | Verified transaction summary, No external links |
| **Malicious URL** | Numeric IP / Spoof | `HIGH` (80/100) | Numeric IP host, Typosquatting token, Suspicious TLD |

---

## 🎓 Viva Voce Questions & Answers (Section 18)

**Q1: What is the core objective of your project?**  
> *"Our project is an AI-based Scam Detection System that analyzes suspicious messages, website URLs, and screenshots to detect potential scam or phishing indicators. It combines NLP, machine learning, URL analysis, and OCR to produce an interpretable risk assessment (0–100), identify possible scam categories, and explain why the input was flagged."*

**Q2: Where and how is AI / Machine Learning used?**  
> *"AI is primarily used in the Natural Language Processing component. We trained and benchmarked 4 algorithms (Multinomial Naive Bayes, Logistic Regression, Linear SVM, and Random Forest) using TF-IDF n-gram vectorization (1-2 ngrams) on labeled scam and legitimate corpora. Logistic Regression was selected as the active model achieving 98.68% accuracy and 98.97% F1-score with calibrated probability outputs."*

**Q3: What makes this project unique compared to a standard spam filter?**  
> *"Traditional spam filters only output a binary 'Spam/Ham' classification. Our system provides: (1) Multi-modal analysis covering text, URLs, and OCR screenshot uploads; (2) An explainable breakdown highlighting specific triggers like urgency, threats, and credential harvesting; (3) Technical URL entropy and IP inspection; and (4) Actionable safety recommendations guiding the user on immediate mitigation steps."*

**Q4: How is the Risk Score computed?**  
> *"The system uses a multi-signal weighted fusion formula:*  
> $$\text{Risk Score} = \min(100, \text{round}(0.40 \times S_{ML} + 0.35 \times S_{Rules} + 0.25 \times S_{URL}))$$  
> *with critical escalation overrides when severe indicators like OTP credential harvesting co-occur with account suspension threats."*

**Q5: What are the limitations of the system?**  
> *"The system is designed as a first-level risk assessment and awareness assistant, not an absolute guarantee. Scammers continually change domains and evasive language, while genuine transactional alerts may occasionally use urgent phrasing. Continuous dataset updates and multi-modal feature expansion remain essential."*

---

## 🛠️ Technology Stack Summary

- **Frontend**: HTML5, Modern CSS (Tailwind CSS, Glassmorphism), Vanilla JavaScript, Chart.js, FontAwesome 6.
- **Client-Side OCR**: Tesseract.js (WebAssembly).
- **Backend API**: Python 3.12, FastAPI, Uvicorn, Pydantic v2.
- **Machine Learning & NLP**: scikit-learn, TF-IDF Vectorizer, joblib, NumPy.
- **Database**: SQLite3.
