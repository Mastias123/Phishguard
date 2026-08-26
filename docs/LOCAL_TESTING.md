# Local Testing Guide

PhishGuard provides multiple ways to test locally without setting up email providers.

## Quick Test

```bash
phishguard test
```

Runs basic component tests:
- Module imports
- Email parsing
- Risk scoring

## Local Analysis Server

Start a local REST API server:

```bash
phishguard server
```

Server runs on `http://localhost:8000`

**Interactive API docs**: http://localhost:8000/docs

### Test with curl

**Analyze sample email:**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "mime_content": "From: test@example.com\nTo: user@example.com\nSubject: Test\n\nTest email body"
  }'
```

**Test endpoint (sample phishing email):**
```bash
curl -X POST http://localhost:8000/analyze/test
```

**Health check:**
```bash
curl http://localhost:8000/health
```

### Example Response

```json
{
  "score": 0,
  "risk_level": "SAFE",
  "summary": "This email appears to be legitimate.",
  "reasons": []
}
```

## Python Testing

**Parse an email:**
```python
from phishguard.mail.parser import MimeParser

mime_content = "From: test@example.com\n..."
email = MimeParser.parse(mime_content)

print(f"From: {email.headers.from_addr}")
print(f"Subject: {email.headers.subject}")
print(f"Links: {email.links}")
```

**Score an email:**
```python
from phishguard.scoring.scorer import RiskScorer

scorer = RiskScorer([])  # No analyzers yet (Phase 3)
result = scorer.score(email)

print(f"Score: {result.score}/100")
print(f"Risk: {result.get_risk_level()}")
print(result.get_formatted_output())
```

**Test fixtures:**
```python
from tests.fixtures import get_phishing_email, get_legitimate_email

phishing_mime = get_phishing_email()
email = MimeParser.parse(phishing_mime)
```

## Component Tests

Run individual test files:

```bash
# Component tests
python backend/tests/test_components.py

# With pytest
pytest backend/tests/ -v
```

## Integration Testing

**Interactive Python shell:**
```bash
source venv/bin/activate
python
>>> from phishguard.mail.parser import MimeParser
>>> from phishguard.scoring.scorer import RiskScorer
>>> 
>>> mime = "From: test@example.com\n..."
>>> email = MimeParser.parse(mime)
>>> scorer = RiskScorer([])
>>> result = scorer.score(email)
>>> print(result.get_formatted_output())
```

## Testing Workflow

1. **Write code** in `backend/phishguard/`
2. **Test locally**:
   ```bash
   python backend/tests/test_components.py
   ```
3. **Test API**:
   ```bash
   phishguard server
   # In another terminal:
   curl -X POST http://localhost:8000/analyze ...
   ```
4. **Commit** with clear message

## Phase 3: When Analyzers Are Added

Once analyzers are implemented, you'll see real detection signals:

```json
{
  "score": 85,
  "risk_level": "VERY HIGH RISK",
  "summary": "This email shows strong indicators of being a phishing attempt.",
  "reasons": [
    {
      "category": "authentication",
      "severity": "high",
      "reason": "SPF validation failed",
      "confidence": 0.95
    },
    {
      "category": "sender",
      "severity": "high",
      "reason": "Sender domain mismatch",
      "confidence": 0.88
    }
  ]
}
```

## Tips

- **Use interactive API docs**: Open http://localhost:8000/docs for Swagger UI
- **Keep server running**: Start in one terminal, test in another
- **Export test emails**: Save MIME content to `.eml` files for testing
- **Debug parsing**: Add print statements to see what's extracted
- **Profile scoring**: Check signal weights in `RiskScorer.SIGNAL_WEIGHTS`

## Troubleshooting

**Server won't start:**
```bash
pip install -e ".[api]"  # Install FastAPI/Uvicorn
```

**Module not found:**
```bash
pip install -e "."  # Reinstall package
```

**Port 8000 already in use:**
```bash
# Kill existing process
lsof -i :8000 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

## Next Steps

- **Phase 2**: Enhance MIME parser with full RFC compliance
- **Phase 3**: Implement phishing analyzers
- **Phase 4**: Add email provider support (IMAP, Microsoft Graph)
