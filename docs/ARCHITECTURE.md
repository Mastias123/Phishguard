# PhishGuard Architecture

Provider-independent phishing detection system for emails.

**Philosophy**: Detect → Warn → User Decides (never auto-delete)

## System Flow

```
Email Source (IMAP/Graph)
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
        ↓
   CLI/API/Extension (user actions)
```

## Modules

**`mail/`** - Email models and parsing
- `models.py` - EmailMessage, EmailHeaders, EmailBody, EmailAttachment
- `parser.py` - MimeParser for MIME message parsing

**`providers/`** - Email provider adapters
- `base.py` - BaseProvider interface
- `imap.py` - IMAP implementation (Phase 4)
- `microsoft_graph.py` - Microsoft Graph implementation (Phase 6)

**`analyzers/`** - Phishing detection
- `base.py` - BaseAnalyzer interface and DetectionSignal
- `authentication.py` - SPF/DKIM/DMARC (Phase 3)
- `sender.py` - Sender analysis (Phase 3)
- `urls.py` - URL/link analysis (Phase 3)
- `content.py` - Content patterns (Phase 3)
- `attachments.py` - Attachment analysis (Phase 3)

**`scoring/`** - Risk scoring
- `signals.py` - DetectionReason, AnalysisResult models
- `scorer.py` - RiskScorer combining signals

**`api/`** - HTTP API layer
- `app.py` - FastAPI application (Phase 5)
- `routes.py` - API endpoints (Phase 5)

## Detection Signals

**Authentication**: SPF/DKIM/DMARC failures
**Sender**: Domain mismatches, brand impersonation
**URLs**: Suspicious links, mismatched display text, redirects
**Content**: Urgency language, account threats, password requests

## Risk Score

- **0-20**: Safe
- **21-40**: Low risk
- **41-60**: Medium risk
- **61-80**: High risk
- **81-100**: Very high (likely phishing)

## Data Processing

1. **Email Retrieval** → Provider fetches raw MIME
2. **Parsing** → MimeParser normalizes to EmailMessage
3. **Analysis** → Analyzers examine for signals
4. **Scoring** → RiskScorer combines signals → final score
5. **Output** → CLI/API/Extension shows score + reasons

## Authentication

**IMAP**: App password or OAuth 2.0  
**Microsoft Graph**: OAuth 2.0 required

## Local Testing

Start the local analysis server:
```bash
phishguard server
```

API available at: http://localhost:8000/docs

**Test with curl:**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"mime_content": "From: test@example.com\n..."}'
```

## Development Phases

1. ✅ **Phase 1** - Repository setup
2. **Phase 2** - Enhanced MIME parser
3. **Phase 3** - Phishing analyzers
4. **Phase 4** - IMAP provider
5. **Phase 5** - Analysis API
6. **Phase 6** - Microsoft Graph provider
7. **Phase 7** - Firefox extension
8. **Phase 8** - Background scanning
9. **Phase 9** - Quarantine functionality
