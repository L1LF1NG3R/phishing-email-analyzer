import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

generic_greetings = [
    r"dear (customer|user|client|member|sir|madam|sir/madam|account holder| valued \w+)",
    r"dear (email|paypal|amazon|bank) (user|customer|member)",
    r"hello (customer|member|client)",
    r"dear friend",
]

generic_urgency_phrases = [
    "urgent", "immediately", "act now", "right away", "asap", "within 24 hours",
    "within 48 hours", "final notice", "last warning", "account will be suspended",
    "account will be closed", "account has been suspended", "account has been locked",
    "verify your account", "confirm your identity", "action required", "immediate action",
    "expires today", "limited time", "failure to comply",
]

url_shorteners = {
    "bit/ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
}

suspicious_tlds = {
    ".zip", ".mov", ".xyz", ".top", ".click", ".work", ".gq", ".tk",
    ".ml", ".cf", ".ga", ".country", ".kim", ".loan", ".men",
}

risky_attachment_extensions = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".ps1", ".msi", ".jar", ".lnk", ".iso", ".img",
    ".html", ".htm", ".hta", ".docm", ".xlsm", ".pptm", ".zip", ".rar",
    ".7z", ".one"
}

data_request_patterns = [
    r"please provide your (password|login credentials|account information|personal information)",
    r"we need your (social security number|credit card number|bank account details)",
    r"update your (billing information|payment method|contact details)",
    r"verify your (identity|account|email address)",
    r"confirm your (personal information|security questions)",
    r"(enter|provide|send|confirm|verify|update|reply with|submit)\b[^.\n]{0,60}\b(password|passcode|pin|username|login|credentials)",
    r"(enter|provide|send|confirm|verify|update|submit)\b[^.\n]{0,60}\b(social security|ssn|tax id|date of birth|dob)",
    r"(enter|provide|send|confirm|verify|update|submit)\b[^.\n]{0,60}\b(credit card|debit card|card number|cvv|cvc|expiration date|routing number|account number|bank details)",
    r"(enter|provide|send|confirm|verify|update|submit)\b[^.\n]{0,60}\b(security question|mother'?s maiden|one[- ]time (code|password)|verification code|2fa code|mfa code)",
    r"(verify|confirm|validate|update) (your )?(account|identity|billing|payment|information|details)",
    r"(log ?in|sign ?in) (to|and) (verify|confirm|update|secure|restore)",
    r"(re-?enter|re-?confirm) your",
]

common_misspellings = [
    "recieve", "acount", "verfiy", "securty", "pasword", "kindly do the needful",
    "dear costumer", "informations", "loging", "immediatly", "confirmation of you",
    "updat your", "clik here", "suspened", "verificaton",
]