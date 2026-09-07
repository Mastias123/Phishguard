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
├── fixtures.py         # Synthetic email fixtures
├── test_components.py  # Legacy component checks
└── test_*.py           # MIME, domain, contextual-rule, and scoring regressions
```

## Commit Workflow

1. Create branch: `git checkout -b feature/name`
2. Make changes
3. Test: `pytest`
4. Commit: `git commit -m "feat(module): description"`
5. Push: `git push origin feature/name`
6. Open PR

**No automatic commits/pushes** - manual control only.

## Adding an Analyzer

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

**Key Principle**: Reported authentication success does not establish sender
trustworthiness. The current analyzer reads supplied headers without independently
verifying them; attackers can also send through legitimate accounts and services.

**Scoring Strategy**:
- Don't dampen detection signals when auth passes
- Use content analysis to distinguish legitimate bulk mail from phishing
- Treat marketing infrastructure only as infrastructure identification, not blanket trust
- Preserve distinct evidence while grouping overlapping findings about the same link
- Give sensitive action/destination context more weight than a generic external link
- Keep country-suffix evidence weak, capped, and conditional on organizational context
- Evaluate score changes on both phishing and legitimate mail; scores are not probabilities

## Extending Context Rules

The parser retains HTML link labels and surrounding text alongside URL strings.
Use that evidence to connect a requested action to its destination. Body keywords
and organization names alone are insufficient to classify an external link.

Organization profiles are optional rule configuration. Add aliases and domains
only with evidence of the relationship, and pass the same profiles to the sender
and URL analyzers. A legitimate service domain may be unrelated to the sender's
name. Scope third-party service domains to the verified action and organization;
do not grant every customer of a payment, marketing, or login platform trust.

Country suffixes are supporting context, not location or ownership verification.
Do not infer an expected country from the language alone or treat `.dk`/`.com` as
safe. Use the shared offline Public Suffix List helper for domain comparisons so
domains such as `first.adv.br` and `second.adv.br` remain distinct.

When extending Danish/English action patterns, add both positive and negative
fixtures. Include legitimate refunds, login notices, payment processors, newsletters,
and international correspondence. Keep sensitive-action evidence tied to the relevant
link, deduplicate repeated evidence, and avoid treating an email's own "test" label
as a trust exemption. See [LOCAL_TESTING.md](LOCAL_TESTING.md) for counterexample pairs.

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

Core: `pydantic`, `dnspython`, `email-validator`, `python-dotenv`,
`tldextract>=5.1.2,<6`, `idna>=3.4`

Domain parsing uses `tldextract`'s bundled suffix snapshot with private suffixes
enabled and runtime fetching/caching disabled. Dependency upgrades can update the
snapshot, so run domain and context regressions after an upgrade.

IMAP: `imapclient`

Microsoft: `azure-identity`, `msgraph-core`

API (future): `fastapi`, `uvicorn`

## 2026-09-07: Link Context and MIME Improvements

- Decode MIME headers and body character sets; preserve both body alternatives and
  structured links with their labels and surrounding text.
- Compare domains with an offline Public Suffix List, including private suffixes.
- Share configurable organization identities between sender and URL checks; evaluate
  sensitive actions against their destination context.
- Keep country evidence conditional and capped, with no language-only inference.
- Group related link evidence in scoring and add regression counterexamples for
  legitimate external services and international messages.

These changes keep analysis local and deterministic. They add no URL fetching,
redirect resolution, live DNS authentication, trained classifier, or automatic action.

## Resources

- [Python Packaging](https://packaging.python.org/)
- [Email RFC 5322](https://tools.ietf.org/html/rfc5322)
- [MIME RFC 2045](https://tools.ietf.org/html/rfc2045)
- [SPF/DKIM/DMARC](https://tools.ietf.org/html/rfc7208)
