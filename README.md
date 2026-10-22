# MailCheck – Email Phishing Analyzer 🔐

**MailCheck** is a Python-based email security analysis tool designed to investigate suspicious emails, identify potential phishing indicators, analyze email headers and content, and check the reputation of URLs, IP addresses, domains, and file hashes using multiple Threat Intelligence sources.

The tool combines email analysis, IOC extraction, heuristic detection, URL deduplication, and external reputation checks through a local browser-based interface to support phishing investigations and defensive cybersecurity workflows.

## ✨ Features

- **Email Parsing:** Analyze raw email source and supported `.eml` files.
- **Header Analysis:** Extract and inspect email headers, sender information, and routing details.
- **Email Authentication:** Identify available SPF, DKIM, DMARC, and ARC authentication information from email headers.
- **Body Analysis:** Inspect email content for suspicious wording, hidden elements, and potential phishing indicators.
- **URL Extraction:** Extract URLs from HTML and plain-text email content.
- **URL Deduplication:** Remove duplicate links, including URLs that differ only by recognized tracking parameters, to make analysis results easier to review.
- **URL Inspection:** Examine extracted URLs, hostnames, and potentially suspicious link patterns.
- **Attachment Analysis:** Identify attachments, calculate SHA-256 hashes, and flag potentially risky file types or extension/MIME mismatches.
- **IOC Extraction:** Collect indicators of compromise (IOCs), including URLs, domains, IPv4 addresses, and attachment hashes where available.
- **Heuristic Detection:** Highlight suspicious patterns that may indicate phishing or malicious activity.
- **Multi-Source Threat Intelligence:** Integrate supported external services to check indicator reputation.
- **VirusTotal Integration:** Retrieve available reputation information for URLs and attachment hashes.
- **AbuseIPDB Integration:** Check IPv4 reputation and reported abusive activity.
- **URLhaus Integration:** Check URLs against known malware-distribution records.
- **PhishTank Integration:** Check URLs against reported phishing records.
- **AlienVault OTX Integration:** Check supported IPs, domains, and file hashes against threat intelligence indicators.
- **Local Web Interface:** Analyze email samples and review results through a browser-based interface running locally.

## 🛠️ Technologies Used

- Python 3
- HTML, CSS, and JavaScript
- Python standard libraries for email parsing, URL processing, hashing, and HTTP communication
- VirusTotal API
- AbuseIPDB API
- URLhaus API
- PhishTank API
- AlienVault Open Threat Exchange (OTX) API

## 📋 Requirements

- Python 3 installed on your system
- A modern web browser
- An internet connection for external Threat Intelligence lookups
- API keys for the services that require authentication

API access requirements and rate limits depend on each provider and your account plan. URLhaus access requirements may vary depending on the endpoint and service policy.

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yasseralaref/MailCheck.git
cd MailCheck
```

### 2. Run the Application

For the enhanced version with multiple Threat Intelligence integrations, run:

```bash
python MailCheck_ThreatIntel.py
```

On Windows, you can also use:

```bash
py MailCheck_ThreatIntel.py
```

If you are using the original VirusTotal-only version, run:

```bash
python MailCheck_VirusTotal.py
```

### 3. Open the Web Interface

Open your browser and navigate to:

```text
http://127.0.0.1:8000
```

Keep the terminal running while using the application.

## 🔍 How to Use

1. Start MailCheck using the appropriate Python script.
2. Open the local web interface in your browser.
3. Provide the raw source of a suspicious email or load an `.eml` file if supported by the interface.
4. Run the email analysis.
5. Review the extracted headers, authentication information, message content, links, attachments, IOCs, and heuristic findings.
6. Review the deduplicated URL list to identify distinct destinations more easily.
7. Enter the required API keys for the Threat Intelligence providers you want to use.
8. Select the relevant **Check** button to query a provider.
9. Compare the returned reputation results and investigate suspicious indicators further.
10. Review the findings in the context of the original email and other available evidence.

## 🧹 URL Deduplication

Email messages, especially automated notifications and marketing emails, often contain repeated links with different tracking parameters.

For example, multiple links may point to the same destination while including parameters such as:

```text
?utm_source=email
&trk=notification
&lipi=tracking_value
```

MailCheck's URL deduplication is designed to reduce this noise by identifying duplicates and removing recognized tracking parameters when comparing URLs.

**Important considerations:**

- Recognized tracking parameters can be ignored when comparing URLs for deduplication.
- The original URL should be retained for investigation and threat intelligence checks.
- URLs with different paths or meaningful query parameters should not automatically be treated as identical.
- Deduplication improves readability but does not determine whether a URL is malicious.
- A unique URL can still contain a phishing page, malicious redirect, or other threat.

The goal is to make the extracted URL list more useful for analysts without losing important security evidence.

## 🦠 Threat Intelligence Integrations

MailCheck supports multiple Threat Intelligence sources to help investigate extracted indicators.

| Provider | Primary purpose |
|---|---|
| **VirusTotal** | URL and file-hash reputation |
| **AbuseIPDB** | IPv4 reputation and abuse reports |
| **URLhaus** | Known malware-distribution URLs |
| **PhishTank** | Reported phishing URLs |
| **AlienVault OTX** | Threat intelligence for supported IPs, domains, and file hashes |

### VirusTotal

Retrieves available reputation information for supported URLs and attachment SHA-256 hashes.

### AbuseIPDB

Checks supported IPv4 addresses against abuse reports and reputation data.

### URLhaus

Checks extracted URLs against records associated with malware distribution.

### PhishTank

Checks extracted URLs against reported phishing records.

### AlienVault OTX

Checks supported indicators against threat intelligence information shared through Open Threat Exchange.

### Important Notes

- Enter API keys through the application interface where required rather than hardcoding them into source code.
- Not every provider supports every indicator type.
- An indicator may not be available in a provider's database.
- Provider errors, quotas, rate limits, or connectivity issues may prevent a lookup from completing.
- A negative result does not prove that an indicator is safe.
- Use multiple sources and contextual analysis when investigating suspicious indicators.
- Review each provider's current terms of service and API limits.

## 🛡️ Security Considerations

- Analyze suspicious emails in a controlled environment.
- Never open suspicious links or execute untrusted attachments during an investigation.
- Avoid sharing email samples containing passwords, authentication tokens, personal information, or confidential business data.
- Treat extracted URLs, domains, IP addresses, and attachment hashes as untrusted until investigated.
- Store API keys securely and never commit them to a public repository.
- Review how external services process submitted indicators before sending sensitive information to them.
- Authentication information extracted from email headers may be missing, forged, or inconclusive.
- Use MailCheck as an investigative aid, not as a replacement for a full security investigation.

## ⚠️ Limitations

- Heuristic findings are signals for further investigation, not definitive proof of phishing.
- SPF, DKIM, DMARC, and ARC results depend on the available message headers and authentication information.
- Threat Intelligence results depend on provider coverage, indicator availability, API access, and rate limits.
- Deduplication can reduce repeated links but cannot determine whether a destination is safe.
- URL reputation checks may not reveal newly created phishing pages, changing redirects, or zero-day threats.
- A clean reputation result does not guarantee that an email, URL, IP address, or attachment is safe.
- The application is intended for local analysis and educational or defensive cybersecurity use.

## 🎯 Project Purpose

MailCheck demonstrates practical concepts in:

- Email threat analysis
- Phishing investigation
- Email header analysis
- Email authentication mechanisms
- URL extraction and deduplication
- IOC extraction and investigation
- File hashing and attachment metadata analysis
- Threat Intelligence integration
- Susp
