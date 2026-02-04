# Security-checker

Security Checker is a lightweight web app for scanning code snippets and documenting common security risks. Paste in Python or JavaScript code, and it will flag risky patterns with severity ratings and suggested fixes.

## Features
- Scan Python and JavaScript snippets for common vulnerability patterns.
- Visual report summary with severity counts.
- Documented findings with remediation guidance.

## Getting started

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000` in your browser.

## Next steps
- Add more language-specific rules and custom templates.
- Export reports to Markdown or JSON.
- Integrate with CI pipelines for continuous scanning.
