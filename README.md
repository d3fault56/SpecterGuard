# SpecterGuard

AI-Powered Scam and Phishing Detection System

SpecterGuard is a real-time threat detection platform that analyzes URLs, emails, and text to identify scams before they cause damage. It combines traditional security checks with AI-based analysis to detect phishing attempts and explain why something is considered dangerous.

---

## Overview

SpecterGuard was built to address the growing number of phishing attacks and online scams. Instead of simply flagging content as malicious, it provides clear explanations and highlights the specific indicators that contributed to the decision.

The system is designed to be practical, fast, and usable in real-world scenarios through both a web dashboard and a browser extension.

---

## Features

- Real-time scam detection
- URL analysis for phishing indicators
- Email analysis including SPF, DKIM, and DMARC checks
- AI-based classification for scam probability
- Confidence scoring with visual feedback
- Identification of common red flags such as:
  - Domain spoofing and typosquatting
  - Credential harvesting attempts
  - Impersonation of trusted services
- Chrome extension for in-browser analysis

---

## How It Works

SpecterGuard evaluates multiple layers of information when analyzing a target:

- Domain-level analysis to detect suspicious patterns and spoofing
- Email authentication checks (SPF, DKIM, DMARC)
- Content analysis for urgency, credential requests, and impersonation
- AI classification to generate a final risk score

Each scan returns:
- A classification (Safe, Suspicious, or Likely Scam)
- A confidence score
- A detailed explanation
- A breakdown of detected red flags

---

## Dashboard

The web interface provides a centralized view for:

- Running scans on text, emails, and URLs
- Viewing scan history
- Tracking threat trends and statistics
- Understanding risk through visual indicators

---

## Chrome Extension

The browser extension allows users to:

- Analyze the current webpage or selected text
- Detect phishing attempts in real time
- View results instantly without leaving the page

---

## Tech Stack

- Backend: Python
- Frontend: HTML, CSS, JavaScript
- AI Integration for classification and analysis
- Chrome Extension (Manifest v3)

---

## Project Structure

specterguard/
├── backend/
├── frontend/
├── extension/
├── screenshots/
├── README.md

---

## Future Improvements

- Mobile application (iOS and Android)
- Public API for integrations
- Automated page scanning and real-time alerts
- Enhanced threat intelligence sources

---

## Status

This project is actively being developed and improved, with a focus on accuracy, usability, and real-world applicability.
