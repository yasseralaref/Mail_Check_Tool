# MailCheck – Email Phishing Analyzer 🔐

**MailCheck** is a Python-based email security analysis tool designed to help investigate suspicious emails, identify potential phishing indicators, and check the reputation of URLs and file attachments using the VirusTotal API.

The tool analyzes email headers, authentication results, message content, links, attachments, and other Indicators of Compromise (IOCs) to support phishing investigations and email threat analysis.

## ✨ Features

- **Email Parsing:** Analyze raw email source or `.eml` files.
- **Header Analysis:** Extract and inspect email headers, including sender information and routing details.
- **Email Authentication:** Identify available SPF, DKIM, DMARC, and ARC authentication results from email headers.
- **Body Analysis:** Inspect email content for suspicious wording and potential phishing indicators.
- **URL Extraction:** Extract links from email content and identify potentially suspicious URLs.
- **Attachment Analysis:** Identify email attachments and calculate SHA-256 hashes for reputation checks.
- **IOC Extraction:** Collect useful indicators, including URLs, domains, IP addresses, and attachment hashes where available.
- **Heuristic Detection:** Highlight suspicious patterns that may indicate phishing or malicious activity.
- **VirusTotal Integration:** Check existing reputation reports for supported URLs and attachment hashes using the VirusTotal API.
- **Local Web Interface:** Interact with the analyzer through a browser-based interface running on your local machine.

## 🛠️ Technologies Used

- Python 3
- HTML, CSS, and JavaScript
- Python standard libraries for email parsing, hashing, and HTTP communication
- VirusTotal API

## 📋 Requirements

- Python 3 installed on your system
- A web browser
- An internet connection for VirusTotal reputation lookups
- A VirusTotal API key for reputation checks

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yasseralaref/MailCheck.git
cd MailCheck
```

> Make sure the repository name is `MailCheck`. If you use a different name, update the clone URL and directory accordingly.

### 2. Run the Application

Run the application using Python:

```bash
python MailCheck_VirusTotal.py
```

On Windows, you can also use:

```bash
py MailCheck_VirusTotal.py
```

### 3. Open the Web Interface

Open your browser and navigate to:

```text
http://127.0.0.1:8000
```

Keep the terminal running while using the application.

## 🔍 How to Use

1. Start the application.
2. Open the local web interface in your browser.
3. Provide the raw source of a suspicious email or load an `.eml` file, depending on the available input options.
4. Run the email analysis.
5. Review the extracted headers, authentication results, body content, links, attachments, and suspicious indicators.
6. Enter your VirusTotal API key in the designated field in the web interface.
7. Select **Check VirusTotal** to retrieve available reputation reports for supported indicators.
8. Review the findings and investigate suspicious indicators further.

## 🦠 VirusTotal Integration

MailCheck uses the VirusTotal API to retrieve existing reputation information for supported URLs and attachment SHA-256 hashes.

**Important Notes:**

- A VirusTotal API key is required for reputation lookups.
- Enter the API key through the application interface rather than hardcoding it into the source code.
- Reputation lookups do not guarantee that an indicator is safe or malicious.
- An unknown or undetected indicator should not automatically be considered safe.
- API quotas and rate limits depend on your VirusTotal account and API plan.
- The application checks existing reputation reports; it does not upload email contents or attachment files for scanning.

## 🛡️ Security Considerations

- Analyze suspicious emails in a controlled environment.
- Never open suspicious links or execute untrusted attachments during an investigation.
- Avoid sharing real email samples containing passwords, authentication tokens, personal information, or confidential business data.
- Treat extracted URLs, domains, and IP addresses as untrusted until verified.
- Store API keys securely and never commit them to a public repository.
- Authentication results may be missing or inconclusive; their absence alone does not prove that an email is malicious.
- Use MailCheck as an investigative aid, not as a replacement for a full security investigation.

## ⚠️ Limitations

- Heuristic findings are indicators for further investigation, not definitive proof of phishing.
- SPF, DKIM, DMARC, and ARC results depend on the information present in the analyzed message.
- VirusTotal results depend on indicator availability, detection coverage, and API access.
- A clean reputation result does not guarantee that an email, URL, or attachment is safe.
- The tool is intended for local analysis and educational or defensive cybersecurity use.

## 🎯 Project Purpose

This project demonstrates practical concepts in:

- Email threat analysis
- Phishing detection
- Email header investigation
- Email authentication mechanisms
- IOC extraction
- File hashing and reputation analysis
- Threat intelligence integration
- Basic incident investigation workflows

## 🔮 Future Improvements

Potential enhancements include:

- More advanced phishing detection rules
- Improved sender and domain reputation analysis
- Integration with additional threat intelligence sources
- Exportable analysis reports
- Better attachment metadata analysis
- Additional detection logic for suspicious redirects and URL obfuscation

##  Author

**Yasser Alaref**


MailCheck is intended for educational, defensive cybersecurity, and authorized security investigation purposes only. The author is not responsible for misuse of this tool. Always follow applicable laws, organizational policies, and the terms of service of any integrated security platform.

---

*Built to support email security analysis and phishing investigations.*
