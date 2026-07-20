from __future__ import annotations

import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
# Requires an assignment-style context (key = "value"), not just a bare
# high-entropy string, to keep the false-positive rate manageable.
GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]([A-Za-z0-9/+_-]{12,})['\"]"
)

CATEGORY_PATTERNS = {
    "Email": EMAIL_RE,
    "SSN": SSN_RE,
    "Phone Number": PHONE_RE,
    "Credit Card": CREDIT_CARD_RE,
    "AWS Access Key": AWS_ACCESS_KEY_RE,
    "Private Key": PRIVATE_KEY_RE,
    "GitHub Token": GITHUB_TOKEN_RE,
    "Slack Token": SLACK_TOKEN_RE,
    "Generic Secret": GENERIC_SECRET_RE,
}

# Categories that, on their own, warrant a High risk rating rather than
# Medium -- credentials and government/payment identifiers vs. lower-signal
# contact info like a bare email or phone number.
SEVERE_CATEGORIES = {
    "SSN",
    "Credit Card",
    "AWS Access Key",
    "Private Key",
    "GitHub Token",
    "Slack Token",
    "Generic Secret",
}


def is_valid_credit_card(candidate: str) -> bool:
    """Luhn checksum, so the loose 13-16-digit regex doesn't flag arbitrary
    long numbers (invoice IDs, phone numbers, order numbers) as card data."""
    digits = [int(c) for c in candidate if c.isdigit()]
    if len(digits) not in (13, 15, 16):
        return False
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0
