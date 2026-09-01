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
phishguard analyze samples/example.eml
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

- ✅ Email parsing (MIME, headers, links)
- ✅ Risk scoring framework
- ✅ CLI test command (`phishguard test`)
- ✅ CLI analysis command (`phishguard analyze <file>`)
- ✅ Authentication analyzer (SPF/DKIM/DMARC)
- ✅ Sender analyzer (impersonation/domain mismatch/homoglyphs)
- ✅ URL analyzer (suspicious links and redirects)
- ✅ Content analyzer (urgency, credentials, obfuscation)
- 🔜 IMAP provider (Phase 4)
- 🔜 Microsoft Graph provider (Phase 6)

## Detection Signals

Analyzes multiple indicators:
- **Authentication**: SPF, DKIM, DMARC outcomes
- **Sender**: Domain mismatches, brand impersonation, homoglyph attacks
- **URLs**: Suspicious links, redirects, host mismatches, tracking hosts
- **Content**: Generic notifications, obfuscation patterns, credential requests, urgency language

**Key Design Principle**: Auth passing (SPF/DKIM/DMARC) proves infrastructure authenticity,
not sender trustworthiness. An attacker can have a legitimate Constant Contact account.

## Usage

**CLI:**
```bash
phishguard test                         # Run basic checks
phishguard analyze samples/email.eml    # Analyze one raw .eml file
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

email = MimeParser.parse(mime_content)
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

Copy `.env.example` to `.env` and configure provider credentials as needed.

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

## Documentation

- [docs/LOCAL_TESTING.md](docs/LOCAL_TESTING.md) - Local testing guide
- [docs/EMAIL_ANALYSIS_GUIDE.md](docs/EMAIL_ANALYSIS_GUIDE.md) - How email risk is evaluated
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) - Dev workflow
- [AGENTS.md](AGENTS.md) - Copilot configuration

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
- **Phase 3** 🟨 Phishing analyzers (content analyzer pending)
- **Phase 4** IMAP provider
- **Phase 5** Analysis API
- **Phase 6** Microsoft Graph provider
- **Phase 7** Firefox extension

## License

MIT - See LICENSE file
