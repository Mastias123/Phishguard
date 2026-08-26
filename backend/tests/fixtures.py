"""Test utilities and fixtures for PhishGuard."""

# Sample test email with phishing indicators
PHISHING_EMAIL_MIME = """From: "MitID Kundeservice" <contat@residenceleprogres.com>
To: user@example.com
Subject: Vigtig sikkerhedsopdatering - Handl nu
Date: Mon, 25 Aug 2026 10:00:00 +0000
Message-ID: <test-phishing-001@example.com>
Authentication-Results: spf=none; dkim=permerror; dmarc=none
Reply-To: support@sender10.zohoinsights.com
DKIM-Signature: v=1; a=rsa-sha256; d=residenceleprogres.com; invalid

Din MitID konto har brug for en vigtig sikkerhedsopdatering.

Dine legitimationsoplysninger er ikke længere gyldige. Klik venligst nedenfor for at opdatere:

https://sender10.zohoinsights.com/update-credentials

Hvis du ikke udfører denne handling inden 24 timer, vil din konto blive låst.

Med venlig hilsen,
MitID Kundeservice
"""

# Sample legitimate email
LEGITIMATE_EMAIL_MIME = """From: GitHub <noreply@github.com>
To: user@example.com
Subject: Your pull request was merged
Date: Mon, 25 Aug 2026 10:00:00 +0000
Message-ID: <github-pr-001@github.com>
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Your pull request #123 has been merged!

https://github.com/username/repo/pull/123

Thanks for contributing!

GitHub
"""


def get_phishing_email():
    """Get test phishing email."""
    return PHISHING_EMAIL_MIME


def get_legitimate_email():
    """Get test legitimate email."""
    return LEGITIMATE_EMAIL_MIME
