# PhishGuard

Provider-independent phishing detection system for emails with explainable risk scores.

## Quick Start

```bash
# Setup
git clone https://github.com/username/phishguard.git
cd phishguard
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install and run checks
pip install -e ".[dev]"
phishguard test

# Analyze a raw email file
phishguard analyze path/to/message.eml
```

## Project Structure

```
backend/phishguard/
├── mail/              # Email models & MIME parsing
├── providers/         # Email provider adapters
├── analyzers/         # Phishing detection logic
├── scoring/           # Risk scoring engine
├── api/               # Future API layer (Phase 5)
└── cli.py             # CLI interface
```

## Current Capabilities

- ✅ MIME parsing with decoded headers, character sets, visible body text, and HTML link labels/context
- ✅ Risk scoring framework
- ✅ CLI test command (`phishguard test`)
- ✅ CLI analysis command (`phishguard analyze <file>`)
- ✅ Authentication analyzer (reported SPF/DKIM/DMARC header outcomes)
- ✅ Sender analyzer (configured organization identity and address mismatches)
- ✅ URL analyzer (displayed destinations, sensitive actions, and destination context)
- ✅ Offline Public Suffix List domain comparisons, including private suffixes
- ✅ Danish/English link-action rules and English content patterns for urgency and credentials
- ✅ Unicode obfuscation checks on extracted body text
- 🔜 IMAP provider (Phase 4)
- 🔜 Microsoft Graph provider (Phase 6)

## Detection Signals

Analyzes multiple indicators:
- **Authentication**: SPF, DKIM, and DMARC results reported in the message headers.
- **Sender**: Configured organization aliases and domains, plus address mismatches.
- **Links**: What a button or anchor asks the recipient to do, what identity it claims,
  and where it leads; misleading displayed domains and basic URL patterns.
- **Content**: Generic notifications, Unicode obfuscation, credential requests, and urgency.
- **Country context**: A small supporting signal only when a sensitive link conflicts
  with a configured organization's expected destination context.

External links are common in legitimate mail. A destination does not need to contain
the sender's name, and a country suffix alone does not determine risk. Organization
profiles can record verified service domains for specific actions without trusting
every link hosted by a third-party platform.

Analysis is local: PhishGuard does not visit links, follow redirects, or perform fresh
SPF/DKIM/DMARC verification. Passing authentication results do not cancel content or
identity warnings. The 0–100 score and rule confidence values are hand-set heuristics,
not calibrated probabilities; even the existing `SAFE` label is not a safety guarantee.

## Usage

**CLI:**
```bash
phishguard test                         # Run basic checks
phishguard analyze path/to/message.eml   # Analyze one raw .eml file
phishguard --help                       # Show commands
```

**Python API:**
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
print(f"Risk: {result.score}/100 ({result.get_risk_level()})")
for reason in result.reasons:
    print(f"  • {reason.reason}")
```

## Configuration

Local `.eml` analysis needs no provider credentials. `.env.example` describes settings
for the planned provider integrations:

```env
# IMAP (One.com, etc.)
IMAP_HOST=imap.one.com
IMAP_PORT=993
IMAP_USERNAME=your-email@domain.com
IMAP_PASSWORD=your-app-password

# Microsoft Graph (Outlook)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
```

## Testing

```bash
phishguard test                           # CLI checks
python backend/tests/test_components.py   # Component tests
pytest backend/tests/ -v                  # Full test suite
```

Regression coverage pairs suspicious messages with legitimate payment services,
international correspondence, and notification links. See the
[analysis guide](docs/EMAIL_ANALYSIS_GUIDE.md) for scoring and configuration limits.

## Documentation

- [docs/LOCAL_TESTING.md](docs/LOCAL_TESTING.md) - Local testing guide
- [docs/EMAIL_ANALYSIS_GUIDE.md](docs/EMAIL_ANALYSIS_GUIDE.md) - How email risk is evaluated
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) - Dev workflow
- [AGENTS.md](AGENTS.md) - Development agent instructions

## Contributing

1. Create feature branch: `git checkout -b feature/name`
2. Make focused changes
3. Run tests
4. Commit with clear messages
5. Open PR

No automatic commits/pushes: keep manual control.

## Roadmap

- **Phase 1** ✅ Setup and documentation
- **Phase 2** ✅ Email parsing and link extraction
- **Phase 3** ✅ Authentication, sender, URL, and content analyzers; ongoing rule improvements
- **Phase 4** IMAP provider
- **Phase 5** Analysis API
- **Phase 6** Microsoft Graph provider
- **Phase 7** Firefox extension

## License

MIT - See LICENSE file
