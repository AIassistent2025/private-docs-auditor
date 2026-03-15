"""Document auditor — PII detection, compliance scanning, risk flags.

All checks are regex/keyword-based and run fully offline.
No data ever leaves the machine.
"""

import re
from pathlib import Path

from pypdf import PdfReader


# ── PII Patterns ──────────────────────────────────────────────────────────────

PII_PATTERNS = {
    "ssn": {
        "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "label": "Social Security Number",
        "severity": "CRITICAL",
    },
    "credit_card": {
        "pattern": re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b"),
        "label": "Credit Card Number",
        "severity": "CRITICAL",
    },
    "email": {
        "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "label": "Email Address",
        "severity": "HIGH",
    },
    "phone_us": {
        "pattern": re.compile(r"\b(?:\+1[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
        "label": "Phone Number (US)",
        "severity": "MEDIUM",
    },
    "iban": {
        "pattern": re.compile(r"\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){2,7}[\dA-Z]{1,4}\b"),
        "label": "IBAN",
        "severity": "HIGH",
    },
    "passport": {
        "pattern": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        "label": "Passport Number (possible)",
        "severity": "MEDIUM",
    },
}

# ── Compliance Frameworks ─────────────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS = {
    "GDPR": {
        "description": "EU General Data Protection Regulation",
        "keywords": [
            "personal data", "data subject", "data controller", "data processor",
            "consent", "right to erasure", "right to be forgotten", "data protection",
            "data breach", "privacy impact", "legitimate interest", "data portability",
            "supervisory authority", "cross-border transfer", "anonymization",
            "pseudonymization", "processing activities",
        ],
    },
    "HIPAA": {
        "description": "Health Insurance Portability and Accountability Act",
        "keywords": [
            "protected health information", "phi", "patient data", "medical record",
            "health plan", "healthcare provider", "covered entity", "business associate",
            "minimum necessary", "notice of privacy", "authorization", "de-identification",
            "electronic health record", "ehr", "treatment payment operations",
        ],
    },
    "SOX": {
        "description": "Sarbanes-Oxley Act",
        "keywords": [
            "internal controls", "financial reporting", "audit committee",
            "material weakness", "significant deficiency", "management assessment",
            "auditor independence", "whistleblower", "certification", "disclosure",
            "section 302", "section 404", "pcaob", "audit trail",
        ],
    },
    "PCI-DSS": {
        "description": "Payment Card Industry Data Security Standard",
        "keywords": [
            "cardholder data", "payment card", "card number", "cvv", "expiration date",
            "encryption", "tokenization", "firewall", "access control",
            "vulnerability scan", "penetration test", "pci compliance",
        ],
    },
}

# ── Risk Keywords ─────────────────────────────────────────────────────────────

RISK_KEYWORDS = {
    "financial": {
        "severity": "HIGH",
        "terms": [
            "default", "overdue", "delinquent", "write-off", "impairment",
            "insolvency", "bankruptcy", "restructuring", "downgrade",
            "material misstatement", "going concern", "liquidity risk",
        ],
    },
    "legal": {
        "severity": "HIGH",
        "terms": [
            "breach", "violation", "penalty", "non-compliance", "lawsuit",
            "litigation", "injunction", "indemnification", "liability",
            "regulatory action", "cease and desist", "class action",
        ],
    },
    "operational": {
        "severity": "MEDIUM",
        "terms": [
            "failure", "outage", "incident", "vulnerability", "unauthorized access",
            "data loss", "system crash", "single point of failure", "downtime",
            "service disruption", "security breach",
        ],
    },
}


# ── Auditor Class ─────────────────────────────────────────────────────────────

class DocumentAuditor:
    """Automated compliance and risk auditor for sensitive documents."""

    def extract_text(self, file_path: str) -> str:
        """Extract text from a PDF or text file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if path.suffix.lower() == ".pdf":
            reader = PdfReader(str(path))
            return "\n".join(page.extract_text() or "" for page in reader.pages)

        return path.read_text(encoding="utf-8")

    def scan_pii(self, text: str) -> dict:
        """Detect PII in text: SSN, credit cards, emails, phones, IBAN, passports.

        Returns:
            {"total_findings": int, "findings": [{"type": str, "severity": str, "count": int, "samples": list}]}
        """
        findings = []
        total = 0

        for pii_type, config in PII_PATTERNS.items():
            matches = config["pattern"].findall(text)
            if matches:
                count = len(matches)
                total += count
                # Mask samples for security
                samples = [self._mask(m) for m in matches[:3]]
                findings.append({
                    "type": config["label"],
                    "severity": config["severity"],
                    "count": count,
                    "samples": samples,
                })

        return {"total_findings": total, "findings": findings}

    def check_compliance(self, text: str, framework: str | None = None) -> dict:
        """Check document against compliance framework(s).

        Args:
            text: Document text.
            framework: Specific framework (GDPR, HIPAA, SOX, PCI-DSS) or None for all.
        """
        text_lower = text.lower()
        frameworks = COMPLIANCE_FRAMEWORKS

        if framework:
            framework_upper = framework.upper()
            if framework_upper not in frameworks:
                return {"error": f"Unknown framework: {framework}. Use: {', '.join(frameworks.keys())}"}
            frameworks = {framework_upper: frameworks[framework_upper]}

        results = {}
        for name, config in frameworks.items():
            matched = []
            for keyword in config["keywords"]:
                count = text_lower.count(keyword.lower())
                if count > 0:
                    matched.append({"keyword": keyword, "occurrences": count})

            relevance = "HIGH" if len(matched) >= 5 else "MEDIUM" if len(matched) >= 2 else "LOW"
            results[name] = {
                "description": config["description"],
                "matched_keywords": len(matched),
                "total_keywords": len(config["keywords"]),
                "relevance": relevance,
                "details": sorted(matched, key=lambda x: x["occurrences"], reverse=True),
            }

        return results

    def flag_risks(self, text: str) -> dict:
        """Identify risk indicators in the document.

        Returns risk findings grouped by category with severity levels.
        """
        text_lower = text.lower()
        results = {}
        total_flags = 0

        for category, config in RISK_KEYWORDS.items():
            found = []
            for term in config["terms"]:
                count = text_lower.count(term.lower())
                if count > 0:
                    found.append({"term": term, "occurrences": count})
                    total_flags += count

            if found:
                results[category] = {
                    "severity": config["severity"],
                    "flags": sorted(found, key=lambda x: x["occurrences"], reverse=True),
                }

        return {"total_flags": total_flags, "categories": results}

    def full_audit(self, file_path: str, framework: str | None = None) -> dict:
        """Run a complete audit: PII scan + compliance check + risk flags.

        Args:
            file_path: Path to document (PDF or text).
            framework: Specific compliance framework or None for all.
        """
        text = self.extract_text(file_path)
        word_count = len(text.split())

        return {
            "file": Path(file_path).name,
            "word_count": word_count,
            "pii_scan": self.scan_pii(text),
            "compliance": self.check_compliance(text, framework),
            "risk_flags": self.flag_risks(text),
        }

    def format_report(self, audit: dict) -> str:
        """Format audit results as a readable Markdown report."""
        lines = [
            f"# Document Audit Report: {audit['file']}",
            f"**Word count:** {audit['word_count']:,}",
            "",
            "---",
            "",
            "## 1. PII Scan",
        ]

        pii = audit["pii_scan"]
        if pii["total_findings"] == 0:
            lines.append("No PII detected.")
        else:
            lines.append(f"**{pii['total_findings']} PII items found:**")
            lines.append("")
            lines.append("| Type | Severity | Count | Samples |")
            lines.append("|---|---|---|---|")
            for f in pii["findings"]:
                samples = ", ".join(f["samples"])
                lines.append(f"| {f['type']} | {f['severity']} | {f['count']} | `{samples}` |")

        lines.extend(["", "## 2. Compliance Check", ""])

        for name, data in audit["compliance"].items():
            lines.append(f"### {name} ({data['description']})")
            lines.append(f"- **Relevance:** {data['relevance']}")
            lines.append(f"- **Keywords matched:** {data['matched_keywords']}/{data['total_keywords']}")
            if data["details"]:
                lines.append("- **Top matches:** " + ", ".join(
                    f"{d['keyword']} ({d['occurrences']})" for d in data["details"][:5]
                ))
            lines.append("")

        lines.extend(["## 3. Risk Flags", ""])

        risks = audit["risk_flags"]
        if risks["total_flags"] == 0:
            lines.append("No risk indicators detected.")
        else:
            lines.append(f"**{risks['total_flags']} risk indicators found:**")
            lines.append("")
            for category, data in risks["categories"].items():
                lines.append(f"### {category.title()} Risk ({data['severity']})")
                for flag in data["flags"]:
                    lines.append(f"- **{flag['term']}** — {flag['occurrences']} occurrence(s)")
                lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _mask(value: str) -> str:
        """Mask a PII value, keeping only first 2 and last 2 characters."""
        if len(value) <= 4:
            return "****"
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
