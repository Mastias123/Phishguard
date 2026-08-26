# PhishGuard Project Specification

## Overview

**PhishGuard** is a provider-independent phishing detection system designed to detect and explain phishing emails across multiple email providers.

### Initial Providers
- **One.com**: Using IMAP protocol
- **Microsoft Outlook / Microsoft 365**: Using Microsoft Graph API

The system is designed to be provider-agnostic, allowing easy addition of new email providers without modifying core analysis logic.

## Core Design Principles

1. **Provider Independence**: Email analysis is completely decoupled from provider implementation
2. **Explainability**: Every phishing score includes detailed reasons and signals
3. **Safety First**: Never automatically delete emails; always prioritize user control
4. **Deterministic Foundation**: Start with rules and heuristics; add AI/LLM as optional signal
5. **Raw Data Analysis**: Analyze MIME headers and raw content, not just formatted text

## Detection Strategy

### Raw Email Data Analyzed
- `From`, `Reply-To`, `Return-Path` headers
- `Received` chain for infrastructure analysis
- `Authentication-Results` (SPF, DKIM, DMARC)
- DKIM signatures and validation
- SPF record results
- DMARC policy results
- HTML and text bodies
- Link destinations and display text
- Attachment metadata

### Detection Signals

#### Authentication Signals
- SPF failure or missing SPF
- DKIM failure/errors
- DMARC failure or missing DMARC

#### Sender Signals
- Sender domain mismatch from display name
- Known brand impersonation
- Display name impersonation

#### URL/Link Signals
- Displayed link vs actual destination mismatch
- Redirect/tracking domains
- Punycode/lookalike domain tricks
- Suspicious external URLs

#### Content Signals
- Urgency language
- Account restriction threats
- Password/account verification requests
- Suspicious attachment patterns
- Unusual sender infrastructure

### Explainable Scoring

Output format example:
```
93 / 100 — Likely phishing

Reasons:
- Brand impersonation
- Sender domain mismatch
- DKIM error
- Suspicious external URL
- Urgency/account restriction language
```

**NOT** just: "AI says 97% phishing"

## Provider Architecture

### Provider Interface
Each provider implements a common interface:
1. Authenticate with service
2. Fetch emails (list and retrieve)
3. Convert to normalized `EmailMessage` model
4. Provide access to raw MIME data

### Generic IMAP Provider
- Supports One.com and other IMAP providers
- App password or OAuth authentication
- Folder/mailbox support

### Microsoft Graph Provider
- Outlook and Microsoft 365 support
- OAuth 2.0 authentication
- Delegated permissions (Mail.Read, etc.)

## Technology Stack

### Backend
- **Language**: Python 3.9+
- **Email Parsing**: email library (stdlib) + custom MIME handling
- **HTTP API**: FastAPI + Uvicorn
- **Data Validation**: Pydantic

### Providers
- **IMAP**: imapclient
- **Microsoft Graph**: azure-identity, msgraph-core

### Frontend (Browser Extension)
- **Language**: TypeScript
- **Framework**: None initially (vanilla TS, WebExtensions API)
- **Target**: Firefox (supports both One.com Webmail and Outlook Web)

## UI/Firefox Extension

### Purpose
Minimal UI layer to display analysis results in webmail interface.

### User Experience

#### Inbox View
```
🔴 93  MitID Kundeservice    Vigtig sikkerhedsopdatering...
🟢  4  GitHub                Your pull request was merged
🟡 48  Invoice Service       Faktura August
```

#### Email Detail View
```
🔴 HIGH RISK · 93/100

Reasons:
• Brand impersonation (MitID Kundeservice)
• Sender domain mismatch
• DKIM error
• Suspicious external URL
• Account restriction language

Actions:
[View Analysis] [Mark Safe] [Mark Phishing] [Quarantine] [Report]
```

### Extension Architecture
- Does NOT rely on HTML scraping
- Backend fetches real email data (IMAP or Graph)
- Extension provides UI layer only
- May integrate with DOM to detect current email

## Automation Modes

### Manual (Default Starting Point)
- User explicitly clicks "Scan" or "Analyze"
- Safest approach for initial release

### Passive (Recommended Default Eventually)
- Automatically analyze all incoming emails
- Display risk indicators
- Do NOT modify or delete emails
- User retains full control

### Protective (Future Enhancement)
- Automatically move very high-risk emails to quarantine
- Still requires user action to delete
- Preserves user control while offering automation

## Critical Safety Decision

**Flow**: Detect → Warn → Optional Quarantine → User Decides

**NOT**: Detect → Delete

False positives are inevitable, so destructive automated actions must be avoided.

## Repository Structure

```
phishguard/
├── AGENTS.md                           # Copilot agent configuration
├── README.md                           # Project overview
├── .gitignore                          # Git ignore rules
├── .env.example                        # Environment template
├── pyproject.toml                      # Python package config
├── requirements.txt                    # Core dependencies
├── requirements-dev.txt                # Dev dependencies
│
├── docs/
│   ├── PROJECT_SPEC.md                 # This file
│   ├── ARCHITECTURE.md                 # Technical architecture
│   ├── SECURITY.md                     # Security guidelines
│   └── DEVELOPMENT.md                  # Dev workflow
│
├── backend/
│   ├── phishguard/
│   │   ├── __init__.py
│   │   ├── mail/                       # Email model & parsing
│   │   │   ├── __init__.py
│   │   │   ├── models.py               # EmailMessage, EmailHeaders
│   │   │   └── parser.py               # MIME parser
│   │   │
│   │   ├── providers/                  # Email provider adapters
│   │   │   ├── __init__.py
│   │   │   ├── base.py                 # BaseProvider interface
│   │   │   ├── imap.py                 # ImapProvider
│   │   │   └── microsoft_graph.py      # MicrosoftGraphProvider
│   │   │
│   │   ├── analyzers/                  # Detection analyzers
│   │   │   ├── __init__.py
│   │   │   ├── base.py                 # BaseAnalyzer interface
│   │   │   ├── authentication.py       # SPF/DKIM/DMARC analysis
│   │   │   ├── sender.py               # Sender analysis
│   │   │   ├── urls.py                 # URL/link analysis
│   │   │   ├── content.py              # Content/urgency analysis
│   │   │   └── attachments.py          # Attachment analysis
│   │   │
│   │   ├── scoring/                    # Risk scoring engine
│   │   │   ├── __init__.py
│   │   │   ├── scorer.py               # RiskScorer
│   │   │   └── signals.py              # Signal definitions
│   │   │
│   │   ├── api/                        # API layer
│   │   │   ├── __init__.py
│   │   │   ├── analysis.py             # AnalysisAPI
│   │   │   ├── app.py                  # FastAPI app
│   │   │   └── routes.py               # API routes
│   │   │
│   │   └── cli.py                      # CLI entry point
│   │
│   └── tests/
│       ├── __init__.py
│       ├── test_mail_parser.py
│       ├── test_analyzers.py
│       ├── test_scoring.py
│       └── fixtures/
│
└── extension/
    ├── manifest.json                   # Firefox extension manifest
    ├── package.json                    # Extension dependencies
    ├── tsconfig.json                   # TypeScript config
    ├── src/
    │   ├── background.ts               # Background script
    │   ├── content.ts                  # Content script
    │   ├── popup.ts                    # Popup UI
    │   └── styles.css                  # Styling
    └── dist/                           # Built extension (generated)
```

## Development Workflow

### Git/Codex Preferences
- Version control with GitHub
- No automatic commits, pushes, or branching
- Professional, descriptive commit messages
- Keep changes small and understandable
- Separate provider code from analysis logic
- Add tests for detection rules
- Explain significant architectural changes before implementing

### Suggested Development Phases

**Phase 1**: Repository setup and documentation ✓
- Repository structure
- Documentation (ARCHITECTURE.md, SECURITY.md, etc.)
- Configuration files

**Phase 2**: Email model and MIME parser
- `EmailMessage` data structure
- MIME/header parsing
- Authentication header extraction
- Link extraction

**Phase 3**: Deterministic analyzers and scoring
- Authentication analyzer (SPF/DKIM/DMARC)
- Sender analyzer
- URL analyzer
- Content analyzer
- Scoring engine

**Phase 4**: IMAP provider
- Generic IMAP provider implementation
- One.com integration and testing
- Email fetching and parsing

**Phase 5**: CLI and testing API
- CLI interface: `phishguard scan`
- Local testing without browser extension
- End-to-end testing

**Phase 6**: Microsoft Graph provider
- Outlook / Microsoft 365 support
- OAuth 2.0 integration
- Graph API email access

**Phase 7**: Firefox extension
- Basic UI structure
- Risk score display
- Integration with analysis API

**Phase 8**: Background scanning
- Automatic email analysis
- Passive mode (analysis without modification)
- Inbox integration

**Phase 9**: Quarantine functionality
- High-risk email quarantine
- User recovery/restore
- Audit logging

## Testing Strategy

1. **Unit Tests**: Individual analyzers, scoring, parsing logic
2. **Integration Tests**: Provider integration, end-to-end analysis
3. **Phishing Dataset**: Real-world phishing examples (anonymized)
4. **Manual Testing**: CLI-based testing of analysis
5. **Browser Testing**: Extension UI and integration

## Security & Safety

- No automatic deletion of emails
- Credentials via environment variables
- Local analysis (minimal data retention)
- User control over all destructive actions
- Audit trail for analysis decisions
- Rate limiting for provider APIs
