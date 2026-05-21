# DataSentinel 🛡️

> Stop leaking secrets before your first push.

DataSentinel is a fast, extensible pre-commit scanner that detects sensitive data (PII, credentials, and secrets) before they reach your Git history.

Built for developers who care about security, privacy, and clean repositories.

---

![DataSentinel Banner](https://dummyimage.com/1200x300/0f172a/ffffff&text=DataSentinel+-+Stop+leaking+secrets+before+your+first+push)

---

## ⚠️ The problem

Accidentally committing sensitive data is surprisingly common:

- API keys pushed to GitHub
- CSV exports with customer emails
- IBANs or BSNs in test datasets
- `.env` files committed by mistake
- logs containing production data

Once it’s in Git history, it’s hard to fully remove—and often already exposed.

---

## 🧭 The solution

DataSentinel scans your staged changes before commit and blocks anything sensitive from being committed.

```bash
git commit -m "add dataset"
```

Example output:

```
┌──────────────────────────────┐
│ DataSentinel Scan Results    │
├──────────────────────────────┤
│ HIGH   OpenAI API Key found  │
│ HIGH   BSN detected          │
│ MEDIUM IBAN detected         │
└──────────────────────────────┘

❌ Commit blocked due to HIGH severity findings.
```

---

## ✨ Features

- Fast scanning of staged Git changes
- Extensible detector system (regex + validators)
- EU-aware PII detection (BSN, IBAN, phone numbers)
- Blocks commits on high-severity findings
- Clean terminal UI (Rich-based)
- Works as pre-commit hook or CI step
- Optional validation logic (not just regex)

---

## 🚀 Installation

```bash
pip install datasentinel
```

Or install from source:

```bash
git clone https://github.com/derklambers/datasentinel
cd datasentinel
pip install -e .
```

---

## 🔧 Usage

### Scan staged files

```bash
datasentinel scan
```

---

### Install as pre-commit hook

```bash
datasentinel install
```

This automatically blocks unsafe commits.

---

## 🧪 Example output

```
Scanning staged files...

customers.csv:14 → BSN detected (HIGH)
customers.csv:22 → email address found (LOW)
.env:2 → OpenAI API key detected (HIGH)

Result: ❌ commit blocked
```

---

## 🧩 Extending DataSentinel

Adding a new detector is simple:

```python
Detector(
    name="AWS Secret Key",
    severity="HIGH",
    pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    mask_value=True,
)
```

Or Dutch-specific detection:

```python
Detector(
    name="Dutch Phone Number",
    severity="LOW",
    pattern=re.compile(r"(\\+31|0)6\\d{8}"),
)
```

---

## 🧠 Architecture

DataSentinel is built around a simple concept:

> detectors = small, composable rules

---

## 🇳🇱 EU-first design

- BSN detection
- IBAN validation
- Dutch phone numbers
- Postal code patterns

---

## 🛣️ Roadmap

- GitHub Action integration
- YAML-based detector config
- AI-based false positive reduction
- Audit dashboard

---

## ⚖️ License

MIT License

---

## 💬 Why DataSentinel?

Security should be automatic, not manual.
