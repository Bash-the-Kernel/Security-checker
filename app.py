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
    severity: str
    description: str
    suggestion: str
    line: int


RULES = {
    "python": [
        {
            "rule_id": "PY001",
            "title": "Dynamic code execution",
            "severity": "High",
            "pattern": r"\b(eval|exec)\s*\(",
            "description": "Using eval/exec can execute untrusted code.",
            "suggestion": "Replace with safe parsing or explicit mappings.",
        },
        {
            "rule_id": "PY002",
            "title": "Insecure deserialization",
            "severity": "High",
            "pattern": r"\bpickle\.loads\s*\(",
            "description": "Pickle can execute arbitrary code when loading untrusted data.",
            "suggestion": "Use json or a safe serialization format.",
        },
        {
            "rule_id": "PY003",
            "title": "Shell injection risk",
            "severity": "Medium",
            "pattern": r"\bsubprocess\.(Popen|call|run)\s*\(.*shell\s*=\s*True",
            "description": "shell=True can allow injection if inputs are not sanitized.",
            "suggestion": "Pass arguments as a list and avoid shell=True.",
        },
        {
            "rule_id": "PY004",
            "title": "Hard-coded secret",
            "severity": "Medium",
            "pattern": r"(?i)(api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]",
            "description": "Secrets in source code can leak credentials.",
            "suggestion": "Move secrets to environment variables or a vault.",
        },
    ],
    "javascript": [
        {
            "rule_id": "JS001",
            "title": "Dynamic code execution",
            "severity": "High",
            "pattern": r"\b(eval|Function)\s*\(",
            "description": "Eval/Function can execute untrusted code.",
            "suggestion": "Use safe parsers or strict input validation.",
        },
        {
            "rule_id": "JS002",
            "title": "DOM XSS sink",
            "severity": "High",
            "pattern": r"\.innerHTML\s*=",
            "description": "Writing to innerHTML can enable XSS with untrusted content.",
            "suggestion": "Use textContent or sanitize HTML.",
        },
        {
            "rule_id": "JS003",
            "title": "Insecure randomness",
            "severity": "Medium",
            "pattern": r"Math\.random\s*\(",
            "description": "Math.random is not cryptographically secure.",
            "suggestion": "Use crypto.getRandomValues or a secure library.",
        },
        {
            "rule_id": "JS004",
            "title": "Hard-coded secret",
            "severity": "Medium",
            "pattern": r"(?i)(apiKey|secret|token)\s*[:=]\s*['\"][^'\"]+['\"]",
            "description": "Secrets in source code can leak credentials.",
            "suggestion": "Use environment variables or secret managers.",
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
    }
    return render_template(
        "index.html",
        language=language,
        code=code,
        findings=findings,
        summary=summary,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
