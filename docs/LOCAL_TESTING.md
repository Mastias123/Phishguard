# Local Testing Guide

PhishGuard can be tested locally without connecting real inbox providers.

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
phishguard analyze samples/example.eml
```

Output includes:
- sender and subject summary
- risk score and risk level
- detection signals with confidence

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

mime_content = "From: test@example.com\n..."
email = MimeParser.parse(mime_content)

scorer = RiskScorer([
    AuthenticationAnalyzer(),
    SenderAnalyzer(),
    URLAnalyzer(),
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

1. Change code under `backend/phishguard/`
2. Run `python backend/tests/test_components.py`
3. Run `phishguard analyze samples/your_test.eml`
4. Confirm scoring and reasons look correct

## Notes

- Sample emails are ignored by git (`samples/*.eml`, etc.) to avoid committing real mails.
- Current analyzer coverage: authentication, sender, URL.
- Content analyzer is the next planned Phase 3 step.