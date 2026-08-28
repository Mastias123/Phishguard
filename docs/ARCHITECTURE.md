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
- `authentication.py` - SPF/DKIM/DMARC validation
- `sender.py` - Sender domain/display name analysis
- `url.py` - URL/link pattern analysis
- `content.py` - Content pattern detection

**`scoring/`** - Risk scoring
- `signals.py` - DetectionReason, AnalysisResult models
- `scorer.py` - RiskScorer combining signals

**`api/`** - HTTP API layer (future)
- `app.py` - FastAPI application (Phase 5)

## Detection Signals

**Authentication**: SPF/DKIM/DMARC outcomes (pass/fail/error)

**Sender**: 
- Domain/display name mismatches
- Brand impersonation
- Reply-To mismatch with sender domain
- Homoglyph attacks (Cyrillic/Latin mixing)

**URLs**: 
- Non-HTTPS schemes
- Link host mismatches with sender domain
- Suspicious keywords (login, verify, account, etc)
- Tracking/redirect hosts (Mailchimp, SendGrid)

**Content**:
- Generic notification themes without tracking/order identifiers
- Unicode obfuscation (soft hyphens, zero-width characters)
- Credential requests (passwords, PINs, 2FA codes)
- Threat/urgency language combined with action requests

## Scoring Weights

Signals are combined using weighted scoring:
- **Authentication** (0.25): SPF/DKIM/DMARC validation
- **Sender** (0.20): Domain/impersonation indicators  
- **URL** (0.30): Link analysis (highest weight)
- **Content** (0.15): Text patterns
- **Attachment** (0.10): Reserved for Phase 8+

**Key Design**: Authentication passing reduces concern about email infrastructure 
but does NOT reduce concerns about sender trustworthiness, URLs, or content. 
An attacker can have a legitimate Mailchimp account.

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

Analyze raw email files locally from CLI:
```bash
phishguard analyze samples/example.eml
```

## Development Phases

1. ✅ **Phase 1** - Repository setup
2. ✅ **Phase 2** - Email models & MIME parsing
3. ✅ **Phase 3** - Phishing analyzers (auth/sender/url/content)
4. 📝 **Phase 4** - IMAP provider
5. 📝 **Phase 5** - REST API
6. 📝 **Phase 6** - Microsoft Graph provider
7. 📝 **Phase 7** - Firefox extension
8. 📝 **Phase 8** - Background scanning
9. 📝 **Phase 9** - Quarantine functionality
