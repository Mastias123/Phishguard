---
name: PhishGuard Development Agent
description: Specialized agent for PhishGuard phishing detection project development
applyTo:
  - /home/mathias/code/Phishguard/**
---

# PhishGuard Development Agent

## Project Context

PhishGuard is a provider-independent phishing detection system for emails. The project uses:
- **Backend**: Python 3.9+
- **Providers**: IMAP (One.com) and Microsoft Graph (Outlook)
- **Frontend**: Firefox browser extension (future)

## Development Preferences

### Git & Version Control
- No automatic commits, pushes, or branch creation
- Professional, descriptive commit messages
- Keep changes small and understandable
- Prefer "git add", "git commit" with clear messages over auto-commit

### Code Organization
- Separate provider code from analysis logic
- One responsibility per module
- Clear abstractions between layers

### Quality Standards
- Add tests for detection rules and new features
- Explain significant architectural changes before implementing
- Type hints on all public functions
- Docstrings (Google style) for classes and public methods
- Clear and professional naming of variables and functions/methods/etc for readability and maintainability

### Module Structure

**Core Layers** (in order of dependency):
1. `mail/` - Email models and MIME parsing (no dependencies on other modules)
2. `providers/` - Email provider adapters (depends on mail/)
3. `analyzers/` - Phishing detection (depends on mail/)
4. `scoring/` - Risk scoring (depends on analyzers/)
5. `api/` - HTTP API layer (depends on scoring/)
6. `cli.py` - Command-line interface (depends on scoring/)

## Development Workflow

### Before Starting a Feature
1. Check [DEVELOPMENT.md](docs/DEVELOPMENT.md) for current phase
2. Create feature branch: `git checkout -b feature/description`
3. Make focused changes
4. Write tests alongside code
5. Commit with clear messages

### Testing
```bash
# Run tests
python backend/tests/test_components.py

# Or with pytest (when available)
pytest backend/tests/ -v

# Run CLI tests
phishguard test
```

### Code Quality
```bash
# Format code
black backend/
isort backend/

# Lint
flake8 backend/ --max-line-length=100
```

## Architecture Principles

### Email Processing Pipeline
```
Raw MIME
  ↓
MimeParser
  ↓
EmailMessage (normalized)
  ↓
Analyzers (parallel)
  ↓
DetectionSignals
  ↓
RiskScorer
  ↓
AnalysisResult (score + reasons)
```

### Key Abstractions
- **BaseProvider**: Interface for email providers
- **BaseAnalyzer**: Interface for phishing detectors
- **RiskScorer**: Combines signals into final score
- **EmailMessage**: Canonical email representation

## Implementation Guidelines

### Adding Analyzers (Phase 3)
All analyzers should:
- Inherit from `BaseAnalyzer`
- Return list of `DetectionSignal` objects
- Include both `confidence` (0.0-1.0) and `severity` (low/medium/high)
- Provide clear `reason` strings for user display

Example:
```python
class MyAnalyzer(BaseAnalyzer):
    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        signals = []
        if condition:
            signals.append(DetectionSignal(
                signal_type="category",
                confidence=0.75,
                reason="Clear user-facing explanation",
                severity="high"
            ))
        return signals
```

### Adding Providers (Phases 4 & 6)
Providers should:
- Inherit from `BaseProvider`
- Convert provider-specific format to `EmailMessage`
- Handle authentication gracefully
- Implement folder/mailbox support

## Current Phase: 1 ✅ (Complete)

**Completed**:
- Project structure and documentation
- Email models and basic MIME parser
- Scoring framework
- CLI with test command
- Virtual environment and package setup

**Next**: Phase 2 - Enhanced MIME parser with comprehensive test coverage

## Common Commands

### Development Setup
```bash
source venv/bin/activate
pip install -e ".[dev]"
```

### Running Tests
```bash
phishguard test
python backend/tests/test_components.py
pytest backend/tests/
```

### Code Formatting
```bash
black backend/ && isort backend/
```

### CLI Help
```bash
phishguard --help
```

## File Organization Rules

- `models.py` - Data classes, no logic
- `parser.py` - Parsing and extraction logic
- `analyzer.py` - Detection logic for specific signal type
- `__init__.py` - Clean exports

## Types & Validation

All public functions should have:
- Parameter type hints
- Return type hints
- Docstring explaining purpose

Example:
```python
def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
    """Analyze email for specific phishing indicators.
    
    Args:
        email: EmailMessage to analyze
        
    Returns:
        List of detected signals (empty if no indicators found)
    """
```

## Decision Log

- ✅ Python backend with Pydantic for validation
- ✅ Deterministic rules-based detection (AI as future signal)
- ✅ Multi-provider abstraction from start
- ✅ Firefox extension (not Chrome initially)
- ✅ No automatic destructive actions (quarantine only)

## Useful Patterns

### Extracting Email Components
```python
# Get sender domain
domain = email.headers.from_addr.split('@')[1] if '@' in email.headers.from_addr else None

# Get display name
display_name = email.get_display_name()

# Get all links
links = email.links
```

### Creating Detection Signals
```python
from phishguard.analyzers.base import DetectionSignal

# Low confidence, informational
signal = DetectionSignal(
    signal_type="info",
    confidence=0.3,
    reason="Minor indicator found",
    severity="low"
)

# High confidence, serious
signal = DetectionSignal(
    signal_type="authentication",
    confidence=0.95,
    reason="SPF validation failed for sender domain",
    severity="high"
)
```

## Phishing Signal Examples

Use these as reference when implementing analyzers:

### Authentication Failures
- SPF record missing or validation failed
- DKIM signature invalid/missing
- DMARC policy failure
- Authentication-Results header shows failures

### Sender Issues
- Display name domain ≠ actual sender domain
- Known brand names in display (impersonation)
- Suspicious email patterns
- First-time sender with urgent request

### URL Indicators
- Link text doesn't match target domain
- External redirect domains
- Typosquatting/punycode tricks
- Known tracking/redirect services

### Content Patterns
- "Verify your account" requests
- Account suspension threats
- Unusual urgency ("within 24 hours")
- Password/credential requests
- Too-good-to-be-true offers

## Testing Philosophy

- Test parsing with real email samples
- Test analyzers independently (unit tests)
- Test scoring combination logic
- Use fixtures for consistent test data
- Keep test emails realistic and documented

---

**Last Updated**: 2026-08-25
**Current Phase**: 1 (Repository Setup - Complete)
**Next Phase**: 2 (Enhanced Email Model & Parsing)
