"""Basic tests for PhishGuard components."""

import sys
sys.path.insert(0, '/home/mathias/code/Phishguard/backend')

from phishguard.mail.models import EmailMessage, EmailHeaders, EmailBody
from phishguard.mail.parser import MimeParser
from phishguard.analyzers.authentication import AuthenticationAnalyzer
from phishguard.analyzers.sender import SenderAnalyzer
from phishguard.analyzers.url import URLAnalyzer
from phishguard.scoring.scorer import RiskScorer
from tests.fixtures import get_phishing_email, get_legitimate_email


def test_mime_parser_phishing_email():
    """Test parsing a phishing email."""
    mime_content = get_phishing_email()
    email = MimeParser.parse(mime_content)
    
    print("\n📧 Parsed Phishing Email:")
    print(f"  From: {email.headers.from_addr}")
    print(f"  Subject: {email.headers.subject}")
    print(f"  Auth Results: {email.headers.authentication_results}")
    print(f"  Sender Domain: {email.sender_domain}")
    print(f"  Display Name Domain: {email.display_name_domain}")
    print(f"  Links found: {len(email.links)}")
    
    assert email.headers.from_addr == '"MitID Kundeservice" <contat@residenceleprogres.com>'
    assert email.sender_domain == "residenceleprogres.com"
    assert len(email.links) > 0
    print("  ✓ Phishing email parsed correctly")


def test_mime_parser_legitimate_email():
    """Test parsing a legitimate email."""
    mime_content = get_legitimate_email()
    email = MimeParser.parse(mime_content)
    
    print("\n📧 Parsed Legitimate Email:")
    print(f"  From: {email.headers.from_addr}")
    print(f"  Subject: {email.headers.subject}")
    print(f"  Auth Results: {email.headers.authentication_results}")
    
    assert "GitHub" in email.headers.from_addr
    assert email.headers.authentication_results is not None
    print("  ✓ Legitimate email parsed correctly")


def test_risk_scorer():
    """Test risk scoring."""
    mime_content = get_phishing_email()
    email = MimeParser.parse(mime_content)
    
    # Score with no analyzers (should return 0)
    scorer = RiskScorer([])
    result = scorer.score(email)
    
    print("\n🎯 Risk Score Result:")
    print(f"  Score: {result.score}/100")
    print(f"  Risk Level: {result.get_risk_level()}")
    print(f"  Summary: {result.summary}")
    
    assert result.score >= 0 and result.score <= 100
    print("  ✓ Scoring works correctly")


def test_authentication_analyzer_scores_phishing_higher():
    """Authentication analyzer should flag failed auth checks."""
    analyzer = AuthenticationAnalyzer()

    phishing_email = MimeParser.parse(get_phishing_email())
    legit_email = MimeParser.parse(get_legitimate_email())

    scorer = RiskScorer([analyzer])
    phishing_result = scorer.score(phishing_email)
    legit_result = scorer.score(legit_email)

    print("\n🔐 Authentication Analyzer Result:")
    print(f"  Phishing score: {phishing_result.score}/100")
    print(f"  Legitimate score: {legit_result.score}/100")

    assert phishing_result.score > legit_result.score
    assert phishing_result.score > 0
    assert legit_result.score == 0
    print("  ✓ Authentication analyzer differentiates phishing from legitimate")


def test_multi_analyzer_pipeline_increases_phishing_score():
    """Sender + URL analyzers should increase phishing confidence."""
    phishing_email = MimeParser.parse(get_phishing_email())
    legit_email = MimeParser.parse(get_legitimate_email())

    auth_only_scorer = RiskScorer([AuthenticationAnalyzer()])
    full_scorer = RiskScorer([
        AuthenticationAnalyzer(),
        SenderAnalyzer(),
        URLAnalyzer(),
    ])

    phishing_auth_only = auth_only_scorer.score(phishing_email)
    phishing_full = full_scorer.score(phishing_email)
    legit_full = full_scorer.score(legit_email)

    print("\n🧠 Multi Analyzer Pipeline Result:")
    print(f"  Phishing (auth only): {phishing_auth_only.score}/100")
    print(f"  Phishing (full): {phishing_full.score}/100")
    print(f"  Legitimate (full): {legit_full.score}/100")

    assert phishing_full.score > phishing_auth_only.score
    assert phishing_full.score > legit_full.score
    print("  ✓ Full analyzer pipeline increases phishing score")


def test_url_analyzer_allows_sibling_subdomains():
    """Links on sibling subdomains of same base domain should not be treated as mismatch."""
    email_mime = """From: \"Indeed\" <donotreply@jobalert.indeed.com>
To: user@example.com
Subject: Job Alerts
Date: Mon, 25 Aug 2026 10:00:00 +0000
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

https://dk.indeed.com/jobs
https://support.indeed.com/help
https://subscriptions.indeed.com/manage
"""

    email_msg = MimeParser.parse(email_mime)
    scorer = RiskScorer([URLAnalyzer()])
    result = scorer.score(email_msg)

    print("\n🔗 URL Analyzer Subdomain Result:")
    print(f"  Score: {result.score}/100")

    mismatch_reasons = [
        reason for reason in result.reasons
        if "does not match sender domain" in reason.reason
    ]

    assert len(mismatch_reasons) == 0
    print("  ✓ Sibling subdomains are not flagged as mismatches")


def test_authenticated_marketing_email_not_maxed_as_phishing():
    """Authenticated bulk email with mixed link hosts should not be auto-maxed."""
    email_mime = """From: coooolstuff <boxgizmo@144875878.mailchimpapp.com>
To: user@example.com
Reply-To: boxgizmo@gmail.com
Subject: Store Newsletter
Date: Mon, 25 Aug 2026 10:00:00 +0000
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

https://www.coooolstuff.com/product
https://t.me/free3dprintmodel
https://gmail.us2.list-manage.com/unsubscribe
https://login.mailchimp.com/signup
"""

    email_msg = MimeParser.parse(email_mime)
    scorer = RiskScorer([
        AuthenticationAnalyzer(),
        SenderAnalyzer(),
        URLAnalyzer(),
    ])
    result = scorer.score(email_msg)

    print("\n📨 Authenticated Marketing Result:")
    print(f"  Score: {result.score}/100")

    assert result.score < 70
    assert result.score > 0
    print("  ✓ Authenticated marketing-style email is not maxed as phishing")


if __name__ == "__main__":
    print("=" * 60)
    print("PhishGuard Component Tests")
    print("=" * 60)
    
    try:
        test_mime_parser_phishing_email()
        test_mime_parser_legitimate_email()
        test_risk_scorer()
        test_authentication_analyzer_scores_phishing_higher()
        test_multi_analyzer_pipeline_increases_phishing_score()
        test_url_analyzer_allows_sibling_subdomains()
        test_authenticated_marketing_email_not_maxed_as_phishing()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
