from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List

from scanner import scan_code, summarize_findings, summarize_owasp

LANGUAGE_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
}


def iter_files(paths: List[str]) -> List[Path]:
    files: List[Path] = []
    for path in paths:
        root = Path(path)
        if root.is_file():
            files.append(root)
            continue
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                files.append(Path(dirpath) / filename)
    return files


def scan_paths(paths: List[str]) -> Dict[str, object]:
    findings = []
    for file_path in iter_files(paths):
        language = LANGUAGE_BY_EXT.get(file_path.suffix.lower())
        if not language:
            continue
        try:
            code = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            code = file_path.read_text(encoding="latin-1")
        for finding in scan_code(code, language):
            finding_dict = finding.to_dict()
            finding_dict["file"] = str(file_path)
            findings.append(finding_dict)
    return {"findings": findings}


def summarize_from_findings(findings: List[Dict[str, object]]) -> Dict[str, object]:
    from scanner import Finding

    converted = [
        Finding(
            rule_id=finding["rule_id"],
            title=finding["title"],
            owasp_id=finding["owasp_id"],
            owasp_title=finding["owasp_title"],
            severity=finding["severity"],
            description=finding["description"],
            suggestion=finding["suggestion"],
            line=finding["line"],
        )
        for finding in findings
    ]
    return {
        "summary": summarize_findings(converted),
        "owasp_summary": summarize_owasp(converted),
    }


def build_markdown(report: Dict[str, object]) -> str:
    lines = [
        "# Security Checker CI Report",
        "",
        f"**Total findings:** {report['summary']['total']}",
        f"**High:** {report['summary']['high']} · "
        f"**Medium:** {report['summary']['medium']} · "
        f"**Low:** {report['summary']['low']}",
        "",
        "## OWASP Top 10 Coverage",
    ]
    for item in report["owasp_summary"]:
        lines.append(
            f"- **{item['owasp_id']} {item['owasp_title']}:** {item['count']} finding"
            f"{'' if item['count'] == 1 else 's'}"
        )
    lines.append("")
    lines.append("## Findings")
    if not report["findings"]:
        lines.append("No issues detected.")
        return "\n".join(lines)
    for finding in report["findings"]:
        lines.extend(
            [
                f"### {finding['title']} ({finding['rule_id']})",
                f"- **File:** {finding['file']}",
                f"- **OWASP:** {finding['owasp_id']} {finding['owasp_title']}",
                f"- **Severity:** {finding['severity']}",
                f"- **Line:** {finding['line']}",
                f"- **Description:** {finding['description']}",
                f"- **Suggested fix:** {finding['suggestion']}",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan repository for security issues.")
    parser.add_argument(
        "--paths",
        nargs="*",
        default=["."],
        help="File or directory paths to scan.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Output format.",
    )
    parser.add_argument(
        "--output",
        default="security-report.json",
        help="Output file path.",
    )
    args = parser.parse_args()

    report = scan_paths(args.paths)
    summary = summarize_from_findings(report["findings"])
    report.update(summary)

    if args.format == "json":
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        Path(args.output).write_text(build_markdown(report), encoding="utf-8")


if __name__ == "__main__":
    main()
