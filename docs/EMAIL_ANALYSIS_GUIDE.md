# How PhishGuard Evaluates an Email

This guide explains what PhishGuard currently checks when you run:

```bash
phishguard analyze path/to/message.eml
```

PhishGuard reads a raw RFC 822/MIME email file, extracts evidence, runs several
independent analyzers, and combines their results into an explainable **risk
score**. It never deletes or quarantines an email automatically.

> Important: the current 0--100 score is a rules-based risk score, not a
> statistically calibrated statement that an email has a particular percentage
> chance of being phishing. A score becomes a true probability only after the
> rules have been tested and calibrated against a large labelled set of genuine
> phishing and legitimate emails.

## Analysis flow

```text
Raw .eml file
  -> MIME parser (headers, body, links, attachments)
  -> authentication, sender, URL, and content analyzers
  -> detection signals with a reason, confidence, and severity
  -> weighted risk score and human-readable report
```

The report should be read as: **"Here is the evidence that needs attention"**,
not as a final judgement about a sender.

## Authentication checks: SPF, DKIM, and DMARC

These three mechanisms help a recipient verify whether an email was sent using
infrastructure authorised by a domain. They are valuable evidence, but they do
not guarantee that the email is safe: an attacker can use a legitimate account
or compromise a real sender's account.

| Mechanism | Plain-language purpose | Example of a problem |
| --- | --- | --- |
| SPF | The sending server is allowed to send mail for a domain. | A server sends mail claiming to be `example.com`, but `example.com` has not authorised it. |
| DKIM | The message has a cryptographic signature that still matches the signed content. | The signature is missing, invalid, or the message was changed after signing. |
| DMARC | Checks that SPF and/or DKIM passed **and align** with the visible From domain; it also gives receivers a policy for failures. | The visible sender is `billing@brand.com`, but the authenticated domain is unrelated. |

### What DMARC validity means

For a message to report `dmarc=pass`, a receiver should find at least one of the
following aligned checks:

1. SPF passes and its authenticated domain matches (or is an allowed subdomain
   of) the visible From domain; or
2. DKIM passes and the DKIM signing domain (`d=`) matches (or is an allowed
   subdomain of) the visible From domain.

This alignment is important. A message can have a passing DKIM signature from a
bulk-email provider but still fail DMARC if it does not align with the visible
brand.

### What PhishGuard currently does

The `AuthenticationAnalyzer` reads the receiving system's
`Authentication-Results` header and looks for `spf=`, `dkim=`, and `dmarc=`
results.

- `pass` adds no risk signal.
- `fail`, `permerror`, or `temperror` adds a high-severity signal.
- `softfail`, `neutral`, or `none` adds a medium-severity signal.
- Missing results add a low or medium-severity signal, because they reduce the
  evidence available; they do not prove phishing.

At present, PhishGuard reports the receiver's stated outcome; it does not yet
perform SPF/DKIM/DMARC verification itself or inspect domain alignment details.
The header must also come from a trusted receiving provider. In an arbitrary raw
email file, an attacker can insert a fake `Authentication-Results` header.

## Sender identity checks

The sender analyzer compares information that should make sense together:

- The display name, such as `MitID Kundeservice`.
- The actual address in the `From` header.
- The `Reply-To` address, if present.

It currently raises signals for a known brand in the display name that is sent
from an unrelated domain, selected high-risk top-level domains, and a `Reply-To`
domain that differs from the sender domain. A mismatch is a reason to inspect an
email, not automatic proof of fraud: newsletters and support systems sometimes
use a separate reply mailbox.

## URL checks

Links are often the most direct phishing evidence. The URL analyzer currently
checks for:

- A link that does not use HTTPS.
- A link host that does not share the sender's base domain.
- Suspicious words in a link host, such as `login`, `verify`, or `secure`.
- Known tracking or redirect hosts.

It avoids flagging normal sibling subdomains as mismatches. It also limits some
false positives for authenticated marketing platforms such as Mailchimp.

Current limitation: URLs are extracted with a text pattern. The next parser
improvement should retain both the visible text of an HTML link and its actual
`href` target. For example, text that says `https://brand.example` but links to
`https://attacker.example` is a very strong signal that the current model cannot
yet evaluate fully.

## Content checks

The content analyzer examines the subject and message body for combinations that
are common in phishing:

- Generic parcel, delivery, or account notifications with no meaningful order,
  reference, or tracking identifier.
- Requests for passwords, PINs, one-time codes, card details, or similar
  credentials.
- Urgency or threats combined with a call to action, for example a threatened
  account suspension followed by a request to click a link.
- Unicode tricks such as zero-width characters or soft hyphens used to evade
  matching and hide words.

Individual words should never decide the outcome on their own. Legitimate
password-reset and delivery messages exist; the useful evidence is a combination
of content, sender identity, authentication, and destination links.

## How the score is calculated today

Each analyzer emits one or more detection signals. A signal has:

- **Reason**: the user-facing explanation.
- **Confidence**: the rule's hand-chosen strength, from 0.0 to 1.0.
- **Severity**: low, medium, or high.

The scorer adds `confidence x category weight x 100` for every signal and caps
the result at 100.

| Category | Current weight |
| --- | ---: |
| Authentication | 25% |
| Sender | 20% |
| URL | 30% |
| Content | 15% |
| Attachment | 10% (reserved; no attachment analyzer yet) |

The displayed bands are: 0--20 Safe, 21--40 Low Risk, 41--60 Medium Risk,
61--80 High Risk, and 81--100 Very High Risk. "Safe" means that the current
rules found no meaningful warning signs; it does not prove the email is genuine.

## Interpreting a report

A strong report has evidence across independent categories, for example:

```text
Display name claims to be MitID, but the From domain is unrelated.
DMARC failed.
The link points to an unrelated login-looking host.
The message demands immediate action and requests credentials.
```

That combination is much more persuasive than one weak indicator, such as a
marketing email using a different reply address.

## Planned improvements

The next analytics milestone should add evidence-rich parsing and validation:

1. Extract HTML link text and targets, respect MIME character sets, and parse
   addresses correctly.
2. Check URL evasion techniques: punycode, IP-address links, misleading
   subdomains, URL shorteners, and unusual ports.
3. Parse SPF/DKIM/DMARC alignment details rather than only reading the result
   header.
4. Add attachment checks for dangerous extensions, double extensions, HTML
   attachments, archives, and macro-enabled documents.
5. Evaluate rules on a labelled set of phishing and legitimate `.eml` files,
   then tune the weights and calibrate any claimed probability.

Optional positive identity evidence can be added later through S/MIME signatures
and BIMI verified-mark certificates. Their absence must remain neutral because
many legitimate senders do not use them.
