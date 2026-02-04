from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from flask import Flask, render_template, request

app = Flask(__name__)


@dataclass
class Finding:
    rule_id: str
    title: str
    owasp_id: str
    owasp_title: str
    severity: str
    description: str
    suggestion: str
    line: int


OWASP_TOP_10 = [
    ("A01", "Broken Access Control"),
    ("A02", "Security Misconfiguration"),
    ("A03", "Software Supply Chain Failures"),
    ("A04", "Cryptographic Failures"),
    ("A05", "Injection"),
    ("A06", "Insecure Design"),
    ("A07", "Authentication Failures"),
    ("A08", "Software or Data Integrity Failures"),
    ("A09", "Security Logging and Alerting Failures"),
    ("A10", "Mishandling of Exceptional Conditions"),
]

RULES = {
    "python": [
        {
            "rule_id": "PY001",
            "title": "Dynamic code execution",
            "owasp_id": "A05",
            "owasp_title": "Injection",
            "severity": "High",
            "pattern": r"\b(eval|exec)\s*\(",
            "description": "Using eval/exec can execute untrusted code.",
            "suggestion": "Replace with safe parsing or explicit mappings.",
        },
        {
            "rule_id": "PY002",
            "title": "Insecure deserialization",
            "owasp_id": "A08",
            "owasp_title": "Software or Data Integrity Failures",
            "severity": "High",
            "pattern": r"\bpickle\.loads\s*\(",
            "description": "Pickle can execute arbitrary code when loading untrusted data.",
            "suggestion": "Use json or a safe serialization format.",
        },
        {
            "rule_id": "PY003",
            "title": "Shell injection risk",
            "owasp_id": "A05",
            "owasp_title": "Injection",
            "severity": "Medium",
            "pattern": r"\bsubprocess\.(Popen|call|run)\s*\(.*shell\s*=\s*True",
            "description": "shell=True can allow injection if inputs are not sanitized.",
            "suggestion": "Pass arguments as a list and avoid shell=True.",
        },
        {
            "rule_id": "PY004",
            "title": "Hard-coded secret",
            "owasp_id": "A02",
            "owasp_title": "Security Misconfiguration",
            "severity": "Medium",
            "pattern": r"(?i)(api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]",
            "description": "Secrets in source code can leak credentials.",
            "suggestion": "Move secrets to environment variables or a vault.",
        },
        {
            "rule_id": "PY005",
            "title": "Debug mode enabled",
            "owasp_id": "A02",
            "owasp_title": "Security Misconfiguration",
            "severity": "Medium",
            "pattern": r"\bDEBUG\s*=\s*True|\bdebug\s*=\s*True",
            "description": "Debug settings can expose sensitive details in production.",
            "suggestion": "Disable debug mode outside local development.",
        },
        {
            "rule_id": "PY006",
            "title": "Weak hashing algorithm",
            "owasp_id": "A04",
            "owasp_title": "Cryptographic Failures",
            "severity": "Medium",
            "pattern": r"\bhashlib\.(md5|sha1)\s*\(",
            "description": "MD5 and SHA1 are considered weak for security-sensitive hashing.",
            "suggestion": "Use SHA-256 or a dedicated password hashing library like bcrypt.",
        },
        {
            "rule_id": "PY007",
            "title": "Potential SQL injection",
            "owasp_id": "A05",
            "owasp_title": "Injection",
            "severity": "High",
            "pattern": r"\bexecute\s*\([^)]*[%{]",
            "description": "Building SQL queries via string interpolation can allow injection.",
            "suggestion": "Use parameterized queries or ORM placeholders.",
        },
        {
            "rule_id": "PY008",
            "title": "Allow-all access control",
            "owasp_id": "A01",
            "owasp_title": "Broken Access Control",
            "severity": "High",
            "pattern": r"\bAllowAny\b|\bpermission_classes\s*=\s*\[AllowAny\]",
            "description": "Allow-any permissions can expose sensitive endpoints.",
            "suggestion": "Require authentication and least-privilege access rules.",
        },
        {
            "rule_id": "PY009",
            "title": "Plaintext password comparison",
            "owasp_id": "A07",
            "owasp_title": "Authentication Failures",
            "severity": "High",
            "pattern": r"\bpassword\s*==\s*['\"][^'\"]+['\"]",
            "description": "Comparing plaintext passwords suggests credentials are stored insecurely.",
            "suggestion": "Store hashed passwords and use constant-time comparisons.",
        },
        {
            "rule_id": "PY010",
            "title": "Unsafe YAML load",
            "owasp_id": "A08",
            "owasp_title": "Software or Data Integrity Failures",
            "severity": "Medium",
            "pattern": r"\byaml\.load\s*\(",
            "description": "yaml.load can construct arbitrary Python objects.",
            "suggestion": "Use yaml.safe_load for untrusted input.",
        },
        {
            "rule_id": "PY011",
            "title": "Runtime package installation",
            "owasp_id": "A03",
            "owasp_title": "Software Supply Chain Failures",
            "severity": "Medium",
            "pattern": r"pip\s+install|pip3\s+install",
            "description": "Installing packages at runtime can introduce unreviewed dependencies.",
            "suggestion": "Install dependencies during build and use lockfiles.",
        },
        {
            "rule_id": "PY012",
            "title": "Security TODO in code",
            "owasp_id": "A06",
            "owasp_title": "Insecure Design",
            "severity": "Low",
            "pattern": r"(?i)(TODO|FIXME):\s*(auth|validate|security)",
            "description": "Security-sensitive TODOs indicate incomplete protections.",
            "suggestion": "Resolve outstanding security tasks before release.",
        },
        {
            "rule_id": "PY013",
            "title": "Silent exception handling",
            "owasp_id": "A09",
            "owasp_title": "Security Logging and Alerting Failures",
            "severity": "Medium",
            "pattern": r"\bexcept\s+Exception\s*:\s*pass",
            "description": "Swallowing exceptions hides security-relevant failures.",
            "suggestion": "Log exceptions and alert on repeated failures.",
        },
        {
            "rule_id": "PY014",
            "title": "Bare except clause",
            "owasp_id": "A10",
            "owasp_title": "Mishandling of Exceptional Conditions",
            "severity": "Medium",
            "pattern": r"\bexcept\s*:\s*pass",
            "description": "Bare except blocks can hide critical failures and leave systems unstable.",
            "suggestion": "Catch specific exceptions and handle errors explicitly.",
        },
    ],
    "javascript": [
        {
            "rule_id": "JS001",
            "title": "Dynamic code execution",
            "owasp_id": "A05",
            "owasp_title": "Injection",
            "severity": "High",
            "pattern": r"\b(eval|Function)\s*\(",
            "description": "Eval/Function can execute untrusted code.",
            "suggestion": "Use safe parsers or strict input validation.",
        },
        {
            "rule_id": "JS002",
            "title": "DOM XSS sink",
            "owasp_id": "A05",
            "owasp_title": "Injection",
            "severity": "High",
            "pattern": r"\.innerHTML\s*=",
            "description": "Writing to innerHTML can enable XSS with untrusted content.",
            "suggestion": "Use textContent or sanitize HTML.",
        },
        {
            "rule_id": "JS003",
            "title": "Insecure randomness",
            "owasp_id": "A04",
            "owasp_title": "Cryptographic Failures",
            "severity": "Medium",
            "pattern": r"Math\.random\s*\(",
            "description": "Math.random is not cryptographically secure.",
            "suggestion": "Use crypto.getRandomValues or a secure library.",
        },
        {
            "rule_id": "JS004",
            "title": "Hard-coded secret",
            "owasp_id": "A02",
            "owasp_title": "Security Misconfiguration",
            "severity": "Medium",
            "pattern": r"(?i)(apiKey|secret|token)\s*[:=]\s*['\"][^'\"]+['\"]",
            "description": "Secrets in source code can leak credentials.",
            "suggestion": "Use environment variables or secret managers.",
        },
        {
            "rule_id": "JS005",
            "title": "Open CORS policy",
            "owasp_id": "A01",
            "owasp_title": "Broken Access Control",
            "severity": "Medium",
            "pattern": r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|cors\s*\(\s*\)",
            "description": "Allowing all origins can expose sensitive endpoints cross-origin.",
            "suggestion": "Restrict CORS to trusted origins.",
        },
        {
            "rule_id": "JS006",
            "title": "Weak crypto hash",
            "owasp_id": "A04",
            "owasp_title": "Cryptographic Failures",
            "severity": "Medium",
            "pattern": r"crypto\.createHash\s*\(\s*['\"](md5|sha1)['\"]",
            "description": "Weak hash algorithms are unsuitable for security-critical data.",
            "suggestion": "Use SHA-256 or stronger cryptographic primitives.",
        },
        {
            "rule_id": "JS007",
            "title": "Potential SQL injection",
            "owasp_id": "A05",
            "owasp_title": "Injection",
            "severity": "High",
            "pattern": r"\.query\s*\(\s*`[^`]*\$\{",
            "description": "Template literals inside SQL queries can allow injection.",
            "suggestion": "Use parameterized queries with placeholders.",
        },
        {
            "rule_id": "JS008",
            "title": "Plaintext password comparison",
            "owasp_id": "A07",
            "owasp_title": "Authentication Failures",
            "severity": "High",
            "pattern": r"password\s*===\s*['\"][^'\"]+['\"]",
            "description": "Plaintext password checks indicate insecure credential handling.",
            "suggestion": "Hash passwords and compare with a constant-time function.",
        },
        {
            "rule_id": "JS009",
            "title": "Unsigned package execution",
            "owasp_id": "A03",
            "owasp_title": "Software Supply Chain Failures",
            "severity": "Medium",
            "pattern": r"npm\s+install|yarn\s+add|pnpm\s+add",
            "description": "Installing packages during runtime can introduce supply chain risk.",
            "suggestion": "Lock dependencies and install during build steps.",
        },
        {
            "rule_id": "JS010",
            "title": "Unchecked JSON parsing",
            "owasp_id": "A08",
            "owasp_title": "Software or Data Integrity Failures",
            "severity": "Low",
            "pattern": r"JSON\.parse\s*\(",
            "description": "Parsing untrusted JSON without validation can introduce integrity issues.",
            "suggestion": "Validate input schemas before parsing.",
        },
        {
            "rule_id": "JS011",
            "title": "Security TODO in code",
            "owasp_id": "A06",
            "owasp_title": "Insecure Design",
            "severity": "Low",
            "pattern": r"(?i)(TODO|FIXME):\s*(auth|validate|security)",
            "description": "Security-sensitive TODOs indicate incomplete protections.",
            "suggestion": "Resolve outstanding security tasks before release.",
        },
        {
            "rule_id": "JS012",
            "title": "Silent catch block",
            "owasp_id": "A09",
            "owasp_title": "Security Logging and Alerting Failures",
            "severity": "Medium",
            "pattern": r"catch\s*\([^)]*\)\s*{\s*}",
            "description": "Empty catch blocks hide errors and prevent alerting.",
            "suggestion": "Log errors and add monitoring hooks.",
        },
        {
            "rule_id": "JS013",
            "title": "Unhandled promise rejection",
            "owasp_id": "A10",
            "owasp_title": "Mishandling of Exceptional Conditions",
            "severity": "Medium",
            "pattern": r"Promise\.reject\s*\(",
            "description": "Rejected promises without handling can crash services or leak data.",
            "suggestion": "Always handle rejections with catch blocks or async error handlers.",
        },
    ],
}


def scan_code(code: str, language: str) -> List[Finding]:
    findings: List[Finding] = []
    rules = RULES.get(language, [])
    for index, line in enumerate(code.splitlines(), start=1):
        for rule in rules:
            if re.search(rule["pattern"], line):
                findings.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        title=rule["title"],
                        owasp_id=rule["owasp_id"],
                        owasp_title=rule["owasp_title"],
                        severity=rule["severity"],
                        description=rule["description"],
                        suggestion=rule["suggestion"],
                        line=index,
                    )
                )
    return findings


@app.route("/", methods=["GET", "POST"])
def index() -> str:
    language = "python"
    code = ""
    findings: List[Finding] = []
    if request.method == "POST":
        language = request.form.get("language", "python")
        code = request.form.get("code", "")
        findings = scan_code(code, language)
    summary = {
        "total": len(findings),
        "high": sum(1 for finding in findings if finding.severity == "High"),
        "medium": sum(1 for finding in findings if finding.severity == "Medium"),
        "low": sum(1 for finding in findings if finding.severity == "Low"),
    }
    owasp_summary = []
    for owasp_id, owasp_title in OWASP_TOP_10:
        count = sum(1 for finding in findings if finding.owasp_id == owasp_id)
        owasp_summary.append(
            {
                "owasp_id": owasp_id,
                "owasp_title": owasp_title,
                "count": count,
            }
        )
    return render_template(
        "index.html",
        language=language,
        code=code,
        findings=findings,
        summary=summary,
        owasp_summary=owasp_summary,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
