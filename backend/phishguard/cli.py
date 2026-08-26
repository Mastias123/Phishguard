"""PhishGuard CLI entry point."""

import sys
from typing import Optional


def main(args: Optional[list] = None) -> int:
    """Main CLI entry point.
    
    Args:
        args: Command line arguments (defaults to sys.argv[1:])
        
    Returns:
        Exit code
    """
    if args is None:
        args = sys.argv[1:]
    
    if not args or args[0] == "--help" or args[0] == "-h":
        print("PhishGuard - Email phishing detection")
        print("Version: 0.1.0")
        print()
        print("Usage: phishguard [command] [options]")
        print()
        print("Commands:")
        print("  test                  Run tests")
        print("  analyze <file>        Analyze email file for phishing")
        print("  version               Show version")
        print("  --help, -h            Show this help")
        print()
        return 0
    
    if args[0] == "test":
        return cmd_test(args[1:])
    elif args[0] == "analyze":
        return cmd_analyze(args[1:])
    elif args[0] == "version":
        print("0.1.0")
        return 0
    else:
        print(f"Unknown command: {args[0]}")
        print("Run 'phishguard --help' for usage")
        return 1


def cmd_test(args: list) -> int:
    """Test command - run basic functionality tests."""
    print("Running PhishGuard tests...")
    
    try:
        # Test imports
        from phishguard.mail.models import EmailMessage, EmailHeaders
        from phishguard.mail.parser import MimeParser
        from phishguard.analyzers.authentication import AuthenticationAnalyzer
        from phishguard.analyzers.sender import SenderAnalyzer
        from phishguard.analyzers.url import URLAnalyzer
        from phishguard.scoring.scorer import RiskScorer
        
        print("✓ Core modules imported successfully")
        
        # Test email parsing
        test_mime = """From: test@example.com
To: user@example.com
Subject: Test Email
Date: Mon, 25 Aug 2026 10:00:00 +0000

This is a test email."""
        
        email_msg = MimeParser.parse(test_mime)
        print(f"✓ Parsed test email: From={email_msg.headers.from_addr}")
        print(f"  Subject: {email_msg.headers.subject}")
        
        # Test scoring
        scorer = RiskScorer([
            AuthenticationAnalyzer(),
            SenderAnalyzer(),
            URLAnalyzer(),
        ])
        result = scorer.score(email_msg)
        print(f"✓ Risk score computed: {result.score}/100 ({result.get_risk_level()})")
        
        print()
        print("All basic tests passed!")
        return 0
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


def cmd_analyze(args: list) -> int:
    """Analyze an email file for phishing indicators."""
    if not args or args[0] in ("--help", "-h"):
        print("Usage: phishguard analyze <email_file>")
        print()
        print("Analyzes an email file and returns phishing risk assessment.")
        print("Email file should be in RFC 2822 format (raw MIME).")
        return 0
    
    file_path = args[0]
    
    try:
        # Read email file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                mime_content = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {file_path}")
            return 1
        except Exception as e:
            print(f"Error reading file: {e}")
            return 1
        
        # Parse email
        from phishguard.mail.parser import MimeParser
        from phishguard.analyzers.authentication import AuthenticationAnalyzer
        from phishguard.analyzers.sender import SenderAnalyzer
        from phishguard.analyzers.url import URLAnalyzer
        from phishguard.scoring.scorer import RiskScorer
        
        email_msg = MimeParser.parse(mime_content)
        
        # Score email with currently implemented analyzers.
        scorer = RiskScorer([
            AuthenticationAnalyzer(),
            SenderAnalyzer(),
            URLAnalyzer(),
        ])
        result = scorer.score(email_msg)
        
        # Display results
        print()
        print("=" * 60)
        print("PHISHING RISK ANALYSIS REPORT")
        print("=" * 60)
        print()
        print(f"From: {email_msg.headers.from_addr}")
        print(f"Display Name: {email_msg.get_display_name()}")
        print(f"Subject: {email_msg.headers.subject}")
        print()
        print(f"Risk Score: {result.score}/100")
        print(f"Risk Level: {result.get_risk_level()}")
        print()
        if result.reasons:
            print("Detection Signals:")
            for reason in result.reasons:
                print(f"  • [{reason.severity.upper()}] {reason.reason}")
                print(f"    Confidence: {reason.confidence:.0%}")
        else:
            print("No phishing indicators detected.")
        print()
        print("=" * 60)
        print()
        return 0
        
    except Exception as e:
        print(f"Error analyzing email: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
