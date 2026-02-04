from __future__ import annotations

from typing import List

from flask import Flask, Response, jsonify, render_template, request

from scanner import Finding, build_report, scan_code, summarize_findings, summarize_owasp

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index() -> str:
    language = "python"
    code = ""
    findings: List[Finding] = []
    if request.method == "POST":
        language = request.form.get("language", "python")
        code = request.form.get("code", "")
        findings = scan_code(code, language)
    summary = summarize_findings(findings)
    owasp_summary = summarize_owasp(findings)
    return render_template(
        "index.html",
        language=language,
        code=code,
        findings=findings,
        summary=summary,
        owasp_summary=owasp_summary,
    )


@app.route("/export/json", methods=["POST"])
def export_json() -> Response:
    language = request.form.get("language", "python")
    code = request.form.get("code", "")
    report = build_report(code, language)
    return jsonify(report)


@app.route("/export/markdown", methods=["POST"])
def export_markdown() -> Response:
    language = request.form.get("language", "python")
    code = request.form.get("code", "")
    report = build_report(code, language)
    markdown = render_template("report.md.j2", **report)
    return Response(
        markdown,
        mimetype="text/markdown",
        headers={"Content-Disposition": "attachment; filename=security-report.md"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
