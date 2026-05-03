# Phishing Domain Generator & Quishing Scanner

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

> **Difficulty:** Beginner | **Language:** Python | **Requires:** requests, qrcode, Pillow, pyzbar

Offensive/defensive toolkit for phishing domain analysis. Generates typosquat variants (keyboard adjacency, omission, transposition, TLD swap) and Unicode homoglyph variants of any domain. Checks which variants are already registered via DNS. Also includes a QR code decoder for "quishing" analysis (QR-code phishing) and a QR code generator for lab use.

---

## Project Structure

```
13-phishing-domain-quishing/
├── README.md
├── .gitignore
├── src/
│   ├── phishing.py       ← Generation + QR decode/generate library
│   ├── main.py           ← CLI: typosquat / homoglyph / qr
│   └── requirements.txt
└── docs/
    └── NOTES.md
```

---

## Installation

```bash
cd src
pip install -r requirements.txt
```

---

## Usage

```bash
# Typosquat variants
python main.py typosquat google.com

# Typosquat + check which are registered (DNS)
python main.py typosquat paypal.com --check

# Unicode homoglyph variants
python main.py homoglyph microsoft.com

# Decode a suspicious QR code
python main.py qr decode suspicious_flyer.png

# Generate a test QR code
python main.py qr generate "https://example.com" --out test.png

# JSON output
python main.py typosquat google.com --json | jq '.[] | select(.registered==true)'
```

**Example output:**
```
[*] Typosquat variants of paypal.com  (87 total)

  Domain                                   Technique        Status
  ──────────────────────────────────────── ──────────────── ────────────
  aypal.com                                omission         available
  payppal.com                              repetition       REGISTERED
  peypal.com                               keyboard-adj     REGISTERED
  papyal.com                               transposition    available
  pay-pal.com                              hyphen-insert    available
  paypal.net                               tld-variant      REGISTERED

[!] 3 registered variant(s)
```

---

## Techniques

| Technique | Example (google.com) |
|-----------|---------------------|
| Omission | gogle.com |
| Repetition | googgle.com |
| Keyboard adjacency | goovle.com (v is adjacent to b) |
| Transposition | googel.com |
| Hyphen insert | goo-gle.com |
| TLD variation | google.net, google.io |
| Brand prefix | logingoogle.com |
| Brand suffix | google-secure.com |
| Homoglyph | gоogle.com (Cyrillic о) |

---

## Quishing (QR Code Phishing)

Quishing is phishing delivered via QR codes in emails, posters, or documents. The QR code bypasses URL-based email filters because the link is encoded as an image. The decoder helps you analyse suspicious QR codes without clicking them.

---

---

## References

- [Unicode confusables](https://www.unicode.org/reports/tr36/)
- [IDN homograph attack — Wikipedia](https://en.wikipedia.org/wiki/IDN_homograph_attack)
- [CISA Quishing advisory](https://www.cisa.gov/news-events/alerts/2023/09/19/cisa-warns-qr-codes-used-energy-company-phishing-attack)
- MITRE ATT&CK: [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)

---

