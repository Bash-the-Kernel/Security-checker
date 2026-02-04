# Security-checker

Security Checker is a lightweight web app for scanning code snippets and documenting common security risks. Paste in Python or JavaScript code, and it will flag risky patterns with severity ratings and suggested fixes.

## Features
- Scan Python and JavaScript snippets for OWASP Top 10 (2025) inspired patterns.
- Visual report summary with severity counts and OWASP category coverage.
- Documented findings with remediation guidance.
- Export reports to JSON or Markdown using custom templates.
- Run repository scans in CI with the included GitHub Actions workflow.

## Getting started

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000` in your browser.

## Export reports
Use the export buttons in the UI or run the CLI to generate reports:

```bash
python scripts/scan_repo.py --format json --output security-report.json
python scripts/scan_repo.py --format markdown --output security-report.md
```

## CI integration
The repository includes `.github/workflows/security-scan.yml`, which runs the scanner on each pull request and uploads a JSON report artifact. Customize the workflow to scan specific paths or fail builds based on severity thresholds.

## Next steps
- Add more language-specific rules and custom templates.
- Export reports to Markdown or JSON.
- Integrate with CI pipelines for continuous scanning.
