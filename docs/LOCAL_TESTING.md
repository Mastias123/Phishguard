# Local Testing Guide

PhishGuard can be tested locally without connecting real inbox providers.

Activate the virtual environment and install the development dependencies first:

```bash
source venv/bin/activate
pip install -e ".[dev]"
```

Analysis uses the Public Suffix List snapshot bundled with `tldextract`. It does not
download a suffix list, use a network cache, or visit destinations while scoring.

## Quick Checks

```bash
phishguard test
```

Runs basic checks for:
- module imports
- MIME parsing
- scoring pipeline

## Analyze a Real Email File

Use a raw RFC822 `.eml` file:

```bash
phishguard analyze path/to/message.eml
```

Output includes:
- sender and subject summary
- risk score and risk level
- detection signals with a reason, severity, and heuristic confidence

The numeric score is not a probability. Inspect the reasons as well as the band;
`SAFE` means a score of 0–20 under the current rules, not verified legitimacy.

## Create a Local Test File

```bash
cat > /tmp/test_mail.eml << 'EOF'
From: test@example.com
To: user@example.com
Subject: Test message
Date: Tue, 26 Aug 2026 10:00:00 +0000
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Hello from a test message.
EOF

phishguard analyze /tmp/test_mail.eml
```

## Python Testing

Parse and score directly:

```python
from phishguard.mail.parser import MimeParser
from phishguard.scoring.scorer import RiskScorer
from phishguard.analyzers.authentication import AuthenticationAnalyzer
from phishguard.analyzers.sender import SenderAnalyzer
from phishguard.analyzers.url import URLAnalyzer
from phishguard.analyzers.content import ContentAnalyzer
from pathlib import Path

email = MimeParser.parse(Path("path/to/message.eml").read_bytes())

scorer = RiskScorer([
    AuthenticationAnalyzer(),
    SenderAnalyzer(),
    URLAnalyzer(),
    ContentAnalyzer(),
])
result = scorer.score(email)

print(result.get_formatted_output())
```

## Component Tests

```bash
python backend/tests/test_components.py
pytest backend/tests/ -v
```

## Testing Workflow

1. Change code under `backend/phishguard/` and add focused fixtures and assertions.
2. Run `pytest backend/tests/ -v` for the full suite. The legacy component script and
   `phishguard test` are smoke checks, not substitutes for the regression suite.
3. Analyze relevant local `.eml` samples and inspect the reasons and risk band.
4. Check a legitimate counterexample for each new detection rule.

Useful regression pairs include:

- An unrelated credential destination versus a configured payment or login service.
- A Danish tax-authority claim with an unexplained `.br` action link versus ordinary
  Danish-language correspondence with a Brazilian business.
- An external newsletter/product link versus a deceptive sensitive-action button.
- A displayed domain that differs from its target versus matching sibling subdomains.
- One action link versus the same evidence repeated across HTML and plain text.
- Entity-encoded or image-labeled actions versus equivalent readable text.

Parser tests should assert the extracted target, label, and local context. Detection
tests should assert the rule evidence and important negative cases. Scoring tests
should check risk bands and duplicate handling, rather than merely asserting that
one score is higher than another.

## Notes

- Sample emails are ignored by git (`samples/*.eml`, etc.) to avoid committing real mails.
- Current analyzer coverage: authentication, sender, URL, and content.
- Parsing accepts MIME bytes or strings. Read real files as bytes so the parser can
  honor the message's declared character sets.
- Link-action rules cover selected Danish and English phrases; standalone content
  rules remain English. These are not a general language model or a complete
  detector for every language.
- A message claiming to be a test, sample, or security exercise is still analyzed;
  text supplied by the sender cannot exempt it from detection.
