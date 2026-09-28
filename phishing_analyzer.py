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
        super().__init__()
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

# checks and compares the displayed sender email compared to the underlying domain of the sender.
def check_mismatched_sender(email_data):
    msg = email_data["msg"]
    reasons = []

    display_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = domain_of(from_addr)

    m = re.search(r"[\w.-]+@[\w.-]+\.\w+|[\w-]+\.(com|net|org|gov|edu)", display_name.lower())
    if m and from_domain and registered_domain(domain_of(m.group(0)) or m.group(0)) != registered_domain(from_domain):
        reasons.append(f"Display name '{display_name}' references a different domain than sender <{from_addr}>")

    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    if reply_addr and from_domain and registered_domain(domain_of(reply_addr)) != registered_domain(from_domain):
        reasons.append(f"Reply-To domain ({domain_of(reply_addr)}) differs from From domain ({from_domain})")

    _, return_addr = parseaddr(str(msg.get("Return-Path", "")))
    if return_addr and from_domain and registered_domain(domain_of(return_addr)) != registered_domain(from_domain):
        reasons.append(f"Return-Path domain ({domain_of(return_addr)}) differs from From domain ({from_domain})")

    auth = str(msg.get("Authentication-Results", "")).lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"{mech}=(fail|softfail|none)", auth):
            reasons.append(f"{mech.upper()} check did not pass")

    return bool(reasons), reasons

# compares the contents of the email with our list of generic greetings.
def check_generic_greeting(email_data):
    opening = email_data["text"].strip()[:300].lower()
    for pattern in generic_greetings:
        m = re.search(pattern, opening)
        if m:
            return True, [f"Generic greeting found: '{m.group(0)}'"]
        return False, []

# compares the contents of the email with our list of false urgency messages.

def check_false_urgency(email_data):
    haystack = (email_data["subject"] + " " + email_data["text"]).lower()
    hits = [p for p in generic_urgency_phrases if p in haystack]
    if hits:
        return True, [f"Urgency/pressure language: {', '.join(hits[:5])}"]
    return False, []

# cleans up the link in an email and checks if it returns a raw ip address, a url shortener, punycode, TLD's, and long subdomains.
def check_suspicious_links(email_data):
    reasons = []
    for href, text in email_data["links"]:
        href = (href or "").strip()
        if not href.lower().startswith(("http://", "https://")):
            continue
        parsed = urlparse(href)
        host = (parsed.hostname or "").lower()

        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            reasons.append(f"Link uses a raw IP address: {href}")
        if host in url_shorteners:
            reasons.append(f"Link uses a URL shortener: {href}")
        if "xn--" in host:
            reasons.append(f"Link uses punycode (possible lookalike domain): {host}")
        if "@" in parsed.netloc:
            reasons.append(f"Link contains '@' in the address (obfuscation trick): {href}")
        if any(host.endswith(tld) for tld in suspicious_tlds):
            reasons.append(f"Link uses a commonly abused TLD: {host}")
        if host.count(".") >= 4:
            reasons.append(f"Link has an unusually long subdomain chain: {host}")
        if parsed.scheme == "http":
            reasons.append(f"Link is not HTTPS: {href}")
 
        shown = re.search(r"([\w-]+\.)+[a-z]{2,}", text.lower())
        if shown and host:
            shown_domain = registered_domain(shown.group(0))
            if shown_domain != registered_domain(host):
                reasons.append(f"Link text shows '{shown.group(0)}' but goes to '{host}'")
 
    reasons = list(dict.fromkeys(reasons))
    return bool(reasons), reasons

# compares the attachment in the email with pre-defined risky file extensions, and it also detects if a file has two extensions.
def check_unexpected_attachments(email_data):
    reasons = []
    for name in email_data["attachments"]:
        lower = name.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if ext in risky_attachment_extensions:
            reasons.append(f"Risky attachment type: {name}")
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|bat|vbs|html?)$", lower):
            reasons.append(f"Double file extension (disguised executable): {name}")
    reasons = list(dict.fromkeys(reasons))
    return bool(reasons), reasons

# checks the email header and body for poor grammar.
def check_poor_grammar(email_data):
    text = email_data["text"]
    lower = text.lower()
    reasons = []

    found = [w for w in common_misspellings if w in lower]
    if found:
        reasons.apend(f"Common phishing misspellings/phrases: {', '.join(found[:4])}")

    if re.search(r"[!?]{2,}", text):
        reasons.append("Repeated punctation (!! or ??)")

    if len(re.findall(r"[a-z][.,!?][A-Za-z]", text)) >= 3:
        reasons.append("Multiple missing spaces after punctuation")

    words = re.findall(r"\b[A-Za-z]{3,}\b", text)
    if words:
        caps_ratio = sum(1 for w in words if w.isupper()) / len(words)
        if caps_ratio > 0.25 and len(words) > 15:
            reasons.append("Excessive ALL CAPS text")

    sentences = [s.strip() for s in re.split(r"[.!?]\s+", text) if len(s.strip()) > 20]
    lowercase_starts = sum(1 for s in sentences if s[0].islower())
    if len(sentences) >= 4 and lowercase_starts / len(sentences) > 0.4:
        reasons.append("Many sentences begin with a lowercase letter")

    return bool(reasons), reasons

def check_data_requests(email_data):
    haystack = (email_data["subject"] + " " + email_data["text"]).lower()
    reasons = []

    for pattern in data_request_patterns:
        m = re.search(pattern, haystack)
        if m:
            snippet = re.sub(r"\s+", " ", m.group(0)).strip()
            reasons.append(f"Asks for sensitive data/action: '{snippet[:80]}'")

    if re.search(r"<input[^>]+type=[\"']?password", email_data["html"].lower()):
        reasons.append("Email contains an embedded password field")
 
    reasons = list(dict.fromkeys(reasons))
    return bool(reasons), reasons

checks = [
    ("Mismatched Sender Address", check_mismatched_sender),
    ("Generic Greetings", check_generic_greeting),
    ("False Urgency", check_false_urgency),
    ("Suspicious Links", check_suspicious_links),
    ("Unexpected Attachments", check_unexpected_attachments),
    ("Poor Grammar", check_poor_grammar),
    ("Requests for Data", check_data_requests),
]

# main function
def analyze(path: str) -> bool:
    email_data = load_email(path)

    print(f"\nAnalyzing: {path}")
    print(f"Subject: {email_data['subject']}")
    print("-" * 60)

    any_triggered = False
    for name, check in checks:
        triggered, reasons = check(email_data)
        any_triggered = any_triggered or triggered
        print(f"[{'X' if triggered else ' '}] {name}")
        for r in reasons:
            print(f"      - {r}")

    print("-" * 60)
    print(f"PHISHING INDCATORS FOUND: {'YES' if any_triggered else 'NO'}\n")
    return any_triggered

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python phishing_analyzer.py path/to/email.eml")
        sys.exit(2)
    result = analyze(sys.argv[1])
    sys.exit(1 if result else 0)