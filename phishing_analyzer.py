import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# patterns for detecting phishing indicators.

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


# handles country code domains.
# (ex. www.example.co.uk -> example.co.uk) or (google.com -> google.com)
def registered_domain(host: str) -> str:
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if parts[-2] in {"co", "com", "net", "org", "gov", "edu", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

# extracts the domain from an email address and removes any leading/trailing whitespace and converts it to lowercase.
def domain_of (address: str) -> str:
    return address.split("@")[-1].lower().strip() if "@" in address else ""

# extracts the html links from the email body (href, text).
class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init_()
        self.links = []
        self._current_href = None
        self._current_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._current_href = dict(attrs).get("href")
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            self.links.append((self._current_href, "".join(self._current_text).strip()))
            self._current_href = None

# loads an email from a file and extracts its subject, text, html, links, and attachments.
def load_email(path: str):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    plain_body, html_body = "", ""
    attachments = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            continue
        if ctype == "text/plain":
            plain_body += content
        elif ctype == "text/html":
            html_body += content

    text = plain_body or re.sub(r"<[^>]+>", " ", html_body)

    links = []
    if html_body:
        extractor = LinkExtractor()
        extractor.feed(html_body)
        links = extractor.links
    for url in re.findall(r"https?://[^\s<>\"')]+", text):
        links.append((url, url))

    return {
        "msg": msg,
        "subject": str(msg.get("Subject", "")),
        "text": text,
        "html": html_body,
        "links": links,
        "attachments": attachments,
    }

def check_mismatched_sender(email_data):
    msg = email_data["msg"]
    reasons = []

    display_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = domain_of(from_addr)

    m = re.search()(r"[\w.-]+@[\w.-]+\.\w+|[\w-]+\.(com|net|org|gov|edu)", display_name.lower())
    if m and from_domain and registered_domain(domain_of(m.group(0)) or m.group(0)) != registered_domain(from_domain):
        reasons.append(f"Display name '{display_name}' references a different domain than sender <{from_addr}>")

    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    if reply_addr and from_domain and registered_domain(domain_of(reply_add)) != registered_domain(from_domain):
        reasons.append(f"Reply-To domain ({domain_of(reply_addr)}) differs from From domain ({from_domain})")

    _, return_addr = parseaddr(str(msg.get("Return-Path", "")))
    if return_addr and from domain and registered_domain(domain_of(return_addr)) != registered_domain(from_domain):
        reasons.append(f"Return-Path domain ({domain_of(return_addr)}) differs from From domain ({from_domain})")

    auth = str(msg.get("Authentication-Results", "")).lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"{mech}=(fail|softfail|none)", auth):
            reasons.append(f"{mech.upper()} check did not pass")

    return bool(reasons), reasons

