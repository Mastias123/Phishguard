# Development Guide

## Setup

```bash
# Clone & setup
git clone https://github.com/username/phishguard.git
cd phishguard
python3 -m venv venv
source venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"
```

## Local Testing

```bash
# Run CLI tests
phishguard test

# Run component tests
python backend/tests/test_components.py

# Run full test suite
pytest backend/tests/ -v
```

## Code Style

```bash
# Format code
black backend/
isort backend/

# Lint
flake8 backend/ --max-line-length=100

# Type check
mypy backend/phishguard
```

## Project Structure

```
backend/phishguard/
├── mail/           # Email models & parsing
├── providers/      # Email provider interfaces
├── analyzers/      # Phishing detection logic
├── scoring/        # Risk scoring
└── cli.py          # CLI interface

backend/tests/
├── fixtures.py     # Test email samples
└── test_components.py  # Component tests
```

## Commit Workflow

1. Create branch: `git checkout -b feature/name`
2. Make changes
3. Test: `pytest`
4. Commit: `git commit -m "feat(module): description"`
5. Push: `git push origin feature/name`
6. Open PR

**No automatic commits/pushes** - manual control only.

## Adding an Analyzer (Phase 3)

Create `backend/phishguard/analyzers/new_analyzer.py`:

```python
from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.mail.models import EmailMessage
from typing import List

class NewAnalyzer(BaseAnalyzer):
    """Detect new phishing indicator."""
    
    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        signals = []
        if suspicious_condition:
            signals.append(DetectionSignal(
                signal_type="category",
                confidence=0.8,
                reason="Clear explanation",
                severity="high"
            ))
        return signals
```

Add to `backend/phishguard/analyzers/__init__.py` and test.

## Scoring Architecture

**Key Principle**: Authentication headers (SPF/DKIM/DMARC passing) prove that an email 
was genuinely sent through the infrastructure it claims to use, but do NOT prove the 
sender is trustworthy. Attackers can have legitimate accounts on services like 
Constant Contact or Mailchimp.

**Scoring Strategy**:
- Don't dampen detection signals when auth passes
- Use content analysis to distinguish legitimate bulk mail from phishing
- Trust marketing infrastructure hosts (Mailchimp, etc) only as infrastructure identification
- Stack multiple signal types (auth + sender + URL + content) for robust scoring

## Phases

| Phase | Status | Tasks |
|-------|--------|-------|
| 1 | ✅ | Setup & docs |
| 2 | ✅ | MIME parsing |
| 3 | ✅ | Analyzers (auth/sender/url/content - all complete) |
| 4 | 📝 | IMAP provider |
| 5 | 📝 | Analysis API |
| 6 | 📝 | Microsoft Graph |
| 7 | 📝 | Firefox extension |

## Dependencies

Core: `pydantic`, `dnspython`, `email-validator`, `python-dotenv`

IMAP: `imapclient`

Microsoft: `azure-identity`, `msgraph-core`

API (future): `fastapi`, `uvicorn`

## Resources

- [Python Packaging](https://packaging.python.org/)
- [Email RFC 5322](https://tools.ietf.org/html/rfc5322)
- [MIME RFC 2045](https://tools.ietf.org/html/rfc2045)
- [SPF/DKIM/DMARC](https://tools.ietf.org/html/rfc7208)
