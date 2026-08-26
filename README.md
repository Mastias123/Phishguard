# PhishGuard

Provider-independent phishing detection system for emails with explainable risk scores.

## Quick Start

```bash
# Setup
git clone https://github.com/username/phishguard.git
cd phishguard
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install & test
pip install -e ".[dev]"
phishguard test

# Run local analysis server
phishguard server
```

Visit: http://localhost:8000/docs

## Project Structure

```
backend/phishguard/
├── mail/              # Email models & MIME parsing
├── providers/         # Email provider adapters
├── analyzers/         # Phishing detection logic
├── scoring/           # Risk scoring engine
├── api/               # Analysis API
└── cli.py             # CLI interface
```

## Current Capabilities

- ✅ Email parsing (MIME, headers, links)
- ✅ Risk scoring framework
- ✅ CLI testing interface
- ✅ Local API server
- 🔜 Phishing analyzers (Phase 2+)

## Detection Signals

Analyzes multiple indicators:
- **Authentication**: SPF, DKIM, DMARC
- **Sender**: Domain mismatches, impersonation
- **URLs**: Suspicious links, redirects
- **Content**: Urgency language, credential requests

## Example

```
93/100 — HIGH RISK
Brand impersonation • Sender domain mismatch • DKIM error • Suspicious URL
```

## Usage

**CLI Testing:**
```bash
phishguard test          # Run tests
phishguard --help        # Show commands
```

**Python API:**
```python
from phishguard.mail.parser import MimeParser
from phishguard.scoring.scorer import RiskScorer

email = MimeParser.parse(mime_content)
result = RiskScorer([]).score(email)
print(result.get_formatted_output())
```

## Configuration

Copy `.env.example` to `.env` and configure:

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
phishguard test                                    # CLI tests
python backend/tests/test_components.py           # Component tests
pytest backend/tests/ -v                          # Full test suite
pytest --cov=phishguard backend/tests/           # With coverage
```

## Documentation

- [LOCAL_TESTING.md](docs/LOCAL_TESTING.md) - Local testing guide
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design
- [DEVELOPMENT.md](docs/DEVELOPMENT.md) - Dev workflow
- [AGENTS.md](AGENTS.md) - Copilot configuration

## Contributing

1. Create feature branch: `git checkout -b feature/name`
2. Make focused changes
3. Write tests: `pytest`
4. Commit with clear messages
5. Open PR

**No automatic commits/pushes** - keep control.

## Roadmap

- **Phase 1** ✅ Setup & documentation  
- **Phase 2** Email parsing & link extraction  
- **Phase 3** Phishing analyzers  
- **Phase 4** IMAP provider  
- **Phase 5** Analysis API  
- **Phase 6** Microsoft Graph  
- **Phase 7** Firefox extension  

## License

MIT - See LICENSE file