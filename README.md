<h1>phishing-email-analyzer</h1>
a python script that analyzes .eml email files against seven common phishing indicators and returns a simple <b>YES/NO</b> verdict, along with the specific reasons behind the flag.

<h2>Background</h2>
built as a hands-on project to practice identifying phishing indicators programmatically.

<h2>How It Works</h2>
the script checks email against seven criteria. if any one of the seven is triggered, the email is flagged as phishing <b>(YES)</b>. if none are triggered, it's marked clean <b>(NO)</b>.

| # | Criteria | What It Looks For |
| --- | --- | --- |
| 1 | mismatched sender address | display name referencing a different domain than the real sender, mismatched reply-to or return-ath, failed SPF/DKIM/DMARC results |
| 2 | generic greetings | openings like "dear customer", "dear user", "valued member", instead of a personal name |
| 3 | false urgency | pressure language such as "act now", "account will be suspended", "within 24 hours" |
| 4 | suspicious links | raw IP addresses, URL shorteners, punycode lookalike domains, @ obfuscation tricks, risky TLDs, non-HTTPS links, and link text that doesn't match the actual destination |
| 5 | unexpected attachments | risky file extensions (.exe, .js, .docm, .html, .zip, etc.) and disguised double extensions like "invoice.pdf.exe" |
| 6 | poor grammar | common phishing misspellings, repeated punctuation, missing spaces after punctuation, excessive ALL CAPS, and sentences starting lowercase |
| 7 | requests for data | language asking the reader to provide passwords, PIN, SSNs, card numbers, security answers, or to "verify"/"confirm" account details |

<h2>Usage</h2>

- python phishing_analyzer.py /path to .eml

<h2>Dataset</h2>
tested against real-world phishing samples from the EPVME Dataset (EPVME_1.zip), a public dataset of phishing emails used for research and detection benchmarking.

- [EPVME Dataset](https://github.com/L1LF1NG3R/interview-email-sorter](https://github.com/sunknighteric/EPVME-Dataset))

<h2>Results</h2>

<b>Suspicious Link Flagged, no HTTPS:</b>
&emsp; <img src="https://imgur.com/XXRvTAa.png" height="80%" width="80%" alt="Result"/> <br/>

<b>Clean Email - No Indicators Triggered</b>
&emsp; <img src="https://imgur.com/XltCnoq.png" height="80%" width="80%" alt="Result"/> <br/>

<b>Suspicious Link & Poor Grammar Flagged</b>
&emsp; <img src="https://imgur.com/f0yPdFB.png" height="80%" width="80%" alt="Result"/> <br/>

<b>Poor Grammar & Requests for Data</b>
&emsp; <img src="https://imgur.com/W4oAzwA.png" height="80%" width="80%" alt="Result"/> <br/>

<h2>Limitations</h2>

- only reads .eml files, not .msg
- the grammar check is a lightweight heuristic, not a natural language processing (NLP). well-written phishing emails can slip past it.
- unexpected attachments are judged only be file type, not by whether the recipient was actually expecting a file. (this can be remedied by confirming with the recipient if they know the sender and if they were expecting the email or attachment before releasing the email into their inbox).
- the any-one-trigger rule means legitimate marketing or notification emails can be flagged. (ex. a real "limited time offer" newsletter)
- keyword and pattern lists (urgency phrases, misspellings, TLDs, etc.) are heuristic starting points and can be tuned as it's tested against more samples.

