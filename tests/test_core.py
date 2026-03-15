"""Tests for Private Docs Auditor — PII, compliance, risk, and config.

All tests run offline without Ollama. No external dependencies needed.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.auditor import DocumentAuditor, PII_PATTERNS, COMPLIANCE_FRAMEWORKS, RISK_KEYWORDS
from src.config import OLLAMA_BASE_URL, DEFAULT_LLM_MODEL, DEFAULT_EMBED_MODEL


# ── Config ────────────────────────────────────────────────────────────────────

class TestConfig:

    def test_ollama_url(self):
        assert OLLAMA_BASE_URL.startswith("http")
        assert "11434" in OLLAMA_BASE_URL

    def test_models_defined(self):
        assert DEFAULT_LLM_MODEL
        assert DEFAULT_EMBED_MODEL


# ── PII Detection ─────────────────────────────────────────────────────────────

class TestPIIDetection:

    def setup_method(self):
        self.auditor = DocumentAuditor()

    def test_detect_ssn(self):
        text = "Employee SSN: 123-45-6789 and another 987-65-4321"
        result = self.auditor.scan_pii(text)
        assert result["total_findings"] == 2
        ssn_finding = next(f for f in result["findings"] if f["type"] == "Social Security Number")
        assert ssn_finding["severity"] == "CRITICAL"
        assert ssn_finding["count"] == 2

    def test_detect_credit_card(self):
        text = "Card: 4111-1111-1111-1111 and 5500 0000 0000 0004"
        result = self.auditor.scan_pii(text)
        cc_findings = [f for f in result["findings"] if f["type"] == "Credit Card Number"]
        assert len(cc_findings) == 1
        assert cc_findings[0]["count"] >= 1

    def test_detect_email(self):
        text = "Contact: john.doe@company.com or admin@example.org"
        result = self.auditor.scan_pii(text)
        email_finding = next(f for f in result["findings"] if f["type"] == "Email Address")
        assert email_finding["count"] == 2
        assert email_finding["severity"] == "HIGH"

    def test_detect_phone(self):
        text = "Call us at (555) 123-4567 or +1 800-555-0199"
        result = self.auditor.scan_pii(text)
        phone_finding = next(f for f in result["findings"] if f["type"] == "Phone Number (US)")
        assert phone_finding["count"] >= 1

    def test_no_pii(self):
        text = "This document contains no personal information whatsoever."
        result = self.auditor.scan_pii(text)
        assert result["total_findings"] == 0
        assert result["findings"] == []

    def test_mask_value(self):
        assert DocumentAuditor._mask("123-45-6789") == "12*******89"
        assert DocumentAuditor._mask("ab") == "****"

    def test_detect_iban(self):
        text = "Payment to IBAN: DE89 3704 0044 0532 0130 00"
        result = self.auditor.scan_pii(text)
        iban_findings = [f for f in result["findings"] if f["type"] == "IBAN"]
        assert len(iban_findings) >= 1


# ── Compliance Check ──────────────────────────────────────────────────────────

class TestComplianceCheck:

    def setup_method(self):
        self.auditor = DocumentAuditor()

    def test_gdpr_detection(self):
        text = (
            "This policy covers personal data processing by the data controller. "
            "Data subjects have the right to erasure and data portability. "
            "Consent must be obtained for all processing activities."
        )
        result = self.auditor.check_compliance(text, framework="GDPR")
        assert "GDPR" in result
        assert result["GDPR"]["relevance"] in ("HIGH", "MEDIUM")
        assert result["GDPR"]["matched_keywords"] >= 4

    def test_hipaa_detection(self):
        text = (
            "All protected health information (PHI) must be secured. "
            "Healthcare providers and covered entities must comply with "
            "minimum necessary standards for patient data access."
        )
        result = self.auditor.check_compliance(text, framework="HIPAA")
        assert result["HIPAA"]["matched_keywords"] >= 3

    def test_sox_detection(self):
        text = (
            "Management assessment of internal controls over financial reporting. "
            "The audit committee reviewed Section 404 compliance. "
            "No material weakness was identified in the audit trail."
        )
        result = self.auditor.check_compliance(text, framework="SOX")
        assert result["SOX"]["matched_keywords"] >= 4

    def test_all_frameworks(self):
        text = "This is a generic business document about operations and sales."
        result = self.auditor.check_compliance(text)
        assert "GDPR" in result
        assert "HIPAA" in result
        assert "SOX" in result
        assert "PCI-DSS" in result

    def test_unknown_framework(self):
        result = self.auditor.check_compliance("text", framework="UNKNOWN")
        assert "error" in result

    def test_no_compliance_matches(self):
        text = "The weather today is sunny with clear skies and warm temperatures."
        result = self.auditor.check_compliance(text, framework="HIPAA")
        assert result["HIPAA"]["matched_keywords"] == 0
        assert result["HIPAA"]["relevance"] == "LOW"


# ── Risk Flags ────────────────────────────────────────────────────────────────

class TestRiskFlags:

    def setup_method(self):
        self.auditor = DocumentAuditor()

    def test_financial_risks(self):
        text = (
            "The borrower is in default on the loan. Two accounts are overdue "
            "and may require write-off. There is a going concern risk."
        )
        result = self.auditor.flag_risks(text)
        assert result["total_flags"] >= 3
        assert "financial" in result["categories"]

    def test_legal_risks(self):
        text = (
            "A breach of contract was identified. The company faces litigation "
            "and a potential class action lawsuit. Regulatory action is expected."
        )
        result = self.auditor.flag_risks(text)
        assert "legal" in result["categories"]
        assert result["categories"]["legal"]["severity"] == "HIGH"

    def test_operational_risks(self):
        text = (
            "The system experienced a major outage and data loss. "
            "A vulnerability was found and unauthorized access was detected."
        )
        result = self.auditor.flag_risks(text)
        assert "operational" in result["categories"]

    def test_no_risks(self):
        text = "The company had a great quarter with strong revenue growth."
        result = self.auditor.flag_risks(text)
        assert result["total_flags"] == 0

    def test_mixed_risks(self):
        text = (
            "The company faces litigation over a data breach. "
            "Several accounts are overdue and an outage affected operations."
        )
        result = self.auditor.flag_risks(text)
        assert len(result["categories"]) >= 2


# ── Full Audit ────────────────────────────────────────────────────────────────

class TestFullAudit:

    def setup_method(self):
        self.auditor = DocumentAuditor()

    def test_full_audit_with_text_file(self):
        content = (
            "Employee record: John Doe, SSN 123-45-6789, email john@company.com.\n"
            "This data is personal data under GDPR. The data controller must ensure consent.\n"
            "Warning: account is overdue and may require write-off."
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = f.name

        try:
            result = self.auditor.full_audit(path)
            assert result["word_count"] > 0
            assert result["pii_scan"]["total_findings"] >= 2  # SSN + email
            assert result["compliance"]["GDPR"]["matched_keywords"] >= 2
            assert result["risk_flags"]["total_flags"] >= 1
        finally:
            os.unlink(path)

    def test_full_audit_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            self.auditor.full_audit("/nonexistent/file.pdf")

    def test_format_report(self):
        content = "Contact: admin@test.com. Account is overdue. Personal data processing."
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = f.name

        try:
            result = self.auditor.full_audit(path)
            report = self.auditor.format_report(result)
            assert "# Document Audit Report" in report
            assert "PII Scan" in report
            assert "Compliance Check" in report
            assert "Risk Flags" in report
        finally:
            os.unlink(path)


# ── Pattern Integrity ─────────────────────────────────────────────────────────

class TestPatternIntegrity:

    def test_all_pii_patterns_compile(self):
        for name, config in PII_PATTERNS.items():
            assert config["pattern"] is not None, f"Pattern {name} failed to compile"
            assert config["label"]
            assert config["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_all_compliance_frameworks_have_keywords(self):
        for name, config in COMPLIANCE_FRAMEWORKS.items():
            assert len(config["keywords"]) >= 5, f"{name} has too few keywords"
            assert config["description"]

    def test_all_risk_categories_have_terms(self):
        for name, config in RISK_KEYWORDS.items():
            assert len(config["terms"]) >= 5, f"{name} has too few terms"
            assert config["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
