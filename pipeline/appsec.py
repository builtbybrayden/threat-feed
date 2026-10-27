"""Application-security relevance classification.

Decides whether an item/CVE is application-security relevant and attaches
ecosystem + vulnerability-class tags, so the pipeline can re-rank toward AppSec
without dropping anything. Rules-first and explainable, like the triage stage.
"""

from __future__ import annotations

import re
from typing import Any

# Ecosystem / platform tag -> keyword list (matched as whole words, lowercase).
ECOSYSTEMS: dict[str, list[str]] = {
    "npm": ["npm", "node.js", "nodejs", "yarn", "pnpm"],
    "pypi": ["pypi", "pip", "python package"],
    "maven": ["maven", "gradle", "java library", "log4j", "log4shell"],
    "rubygems": ["rubygems", "ruby gem"],
    "nuget": ["nuget", ".net package"],
    "composer": ["composer", "packagist", "php package"],
    "go": ["go module", "golang"],
    "php": ["php", "wordpress", "drupal", "joomla", "laravel", "symfony"],
    "web": [
        "wordpress", "drupal", "joomla", "laravel", "symfony", "django", "flask",
        "rails", "express", "spring", "struts", "tomcat", "confluence", "jira",
        "gitlab", "jenkins", "sharepoint", "graphql", "nextjs", "react",
    ],
    "supply-chain": [
        "dependency confusion", "supply chain", "typosquat", "malicious package",
    ],
}

# Vulnerability-class (DAST) tag -> keyword list.
VULN_CLASSES: dict[str, list[str]] = {
    "sqli": ["sql injection", "sqli"],
    "xss": ["cross-site scripting", "xss"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "xxe": ["xxe", "xml external entity"],
    "deserialization": ["deserialization", "deserialisation"],
    "path-traversal": ["path traversal", "directory traversal"],
    "prototype-pollution": ["prototype pollution"],
    "ssti": ["template injection", "ssti"],
    "rce": ["remote code execution", "rce"],
    "auth-bypass": ["authentication bypass", "auth bypass"],
    "command-injection": ["command injection"],
}

# NVD CWE ids that are inherently application-layer web issues.
APPSEC_CWES = {20, 22, 74, 77, 78, 79, 89, 90, 94, 352, 434, 502, 611, 843, 862, 915, 917, 918, 1321}


def _hits(text: str, mapping: dict[str, list[str]]) -> list[str]:
    tags = []
    for tag, terms in mapping.items():
        for term in terms:
            pattern = r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])"
            if re.search(pattern, text):
                tags.append(tag)
                break
    return tags


def classify_text(*texts: str | None) -> dict[str, Any]:
    """AppSec signals derivable from free text (titles/summaries/descriptions)."""
    blob = " ".join(t for t in texts if t).lower()
    ecosystems = _hits(blob, ECOSYSTEMS)
    classes = _hits(blob, VULN_CLASSES)
    return {
        "ecosystems": ecosystems,
        "vuln_classes": classes,
        "appsec": bool(ecosystems or classes),
    }


def classify_cve(rec, config: dict[str, Any]) -> dict[str, Any]:
    """AppSec relevance for an enriched CVE record: text + CWE + CPE evidence."""
    base = classify_text(rec.description, rec.product, rec.vendor, " ".join(rec.cwe))
    cwe_ids = {int(m.group()) for c in rec.cwe if (m := re.search(r"\d+", c))}
    cwe_appsec = bool(cwe_ids & APPSEC_CWES)
    app_cpe = any(":a:" in cpe for cpe in rec.cpes)  # CPE application part
    appsec = base["appsec"] or cwe_appsec or app_cpe
    reasons = []
    if base["ecosystems"]:
        reasons.append("ecosystem: " + ", ".join(base["ecosystems"]))
    if base["vuln_classes"]:
        reasons.append("class: " + ", ".join(base["vuln_classes"]))
    if cwe_appsec:
        reasons.append("web CWE")
    elif app_cpe and not base["appsec"]:
        reasons.append("application CPE")
    return {
        "appsec": appsec,
        "ecosystems": base["ecosystems"],
        "vuln_classes": base["vuln_classes"],
        "reasons": reasons,
    }
