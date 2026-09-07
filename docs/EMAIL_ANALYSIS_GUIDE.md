# How PhishGuard Evaluates an Email

Run the local analyzer on a raw email file:

```bash
phishguard analyze path/to/message.eml
```

PhishGuard extracts evidence, applies deterministic rules, and reports the
reasons behind a heuristic risk score. It does not follow links, send messages,
delete mail, or quarantine it.

This guide teaches email analysis first and describes the current PhishGuard
implementation second. A human analyst can inspect more evidence than the
application currently automates.

## 1. How Email Analysis Works

Phishing is rarely proved by one unusual property. A legitimate newsletter may
use a separate tracking domain, a genuine password-reset email may request a
sign-in, and an international business may link to a country-code domain. Each is
evidence to investigate, not a verdict.

An analyst asks whether independent observations tell a coherent story:

```text
Claimed identity        Who does the message say it is from?
Observed identities     Which domains sent, signed, or receive replies?
Requested action        What does it ask the recipient to do?
Destination             Where does that action actually lead?
Authentication          Which identity did the receiver verify?
                         ↓
                  combined evidence
```

For example, a request to confirm an identity can be normal. It is much more
concerning when a display name claims to be a tax authority, the From address is
unrelated, and the confirmation button leads to an unexplained website.

Four terms are useful throughout this guide:

- **Evidence** is an observed fact, such as a `Reply-To` address or link target.
- **An analysis rule** is a repeatable interpretation of evidence.
- **A detection signal** is the reason and heuristic strength emitted when a
  PhishGuard rule applies.
- **The risk score** combines signals to prioritize review.

The 0–100 score and a signal's confidence are hand-chosen heuristics. They are
not measured probabilities. A score of 80 does not mean an 80% chance the email
is phishing; that requires calibration against a large, representative labelled
collection of malicious and legitimate email.

## 2. Parsing and Evidence Extraction

### What is in an `.eml` message?

An email has headers followed by a body:

```text
Headers
  From, To, Subject, Return-Path, Received, Authentication-Results, ...

Body
  one or more MIME parts: plain text, HTML, attachments, embedded messages, ...
```

Headers describe routing and declared identities. Some come from the sender;
others are added by mail systems, so their source matters. MIME lets a message
carry plain-text and HTML alternatives.

HTML gives an important distinction. A link has visible text and an actual
destination:

```html
<a href="https://account-check.example/sign-in">https://www.example-bank.dk</a>
```

The label suggests the bank domain, while `href` controls the click. An analyst
needs both. Nearby text matters too: `Continue` is ambiguous alone, but its
paragraph may say “confirm your identity with MitID.”

Email headers and body parts can use character sets and transfer encodings. If
they are not decoded, a subject, sender name, or text such as `Bekræft` can be
unreadable and rules can miss relevant evidence.

### What PhishGuard currently preserves

`MimeParser` accepts raw bytes or text. The CLI reads files as bytes so it can
decode declared MIME character sets and transfer encodings. It decodes headers,
parses mailbox addresses, collects visible plain-text and HTML content, and keeps
attachment bodies out of ordinary body analysis.

For every link it preserves its destination URL, visible anchor label (including
an image's `alt` text when available), and bounded nearby text from the same
paragraph or HTML container. `email.links` is a unique URL list;
`email.link_details` contains `EmailLink(url, text, context)`; and
`email.body.visible_text` is the readable text used by body analysis.

Both plain-text and HTML alternatives can contribute evidence. HTML entities are
decoded and obvious hidden, script, and style content is excluded. This is not a
browser: PhishGuard does not execute JavaScript, fetch resources, perform OCR, or
reproduce every CSS rule.

## 3. Authentication Analysis

Authentication answers a narrower question than it may appear to: *did the
receiver verify that a domain authorized the sending infrastructure or signed
selected content?* It does not answer *is this organization honest?*

### Understanding email identities

One email can contain several identities with different purposes:

| Identity | Example | What it is for |
| --- | --- | --- |
| SMTP `MAIL FROM` / envelope sender | `bounce@mailer.example` | Used during delivery; normally evaluated by SPF. |
| `Return-Path` | `<bounce@mailer.example>` | A delivery-system record of the envelope sender. |
| `From` | `Example Bank <news@example-bank.dk>` | The identity shown to the reader. |
| `Reply-To` | `support@helpdesk.example` | Where replies are directed, if present. |
| DKIM `d=` domain | `d=mailer.example` | The domain that signed selected message data. |

These values can legitimately differ. A retailer may send through a mailing
platform, use a bounce address, and route replies to a help desk. They can also
differ because an attacker controls several unrelated domains. The task is to
understand the relationships, not demand that every field be identical.

### SPF: authorization of a sending server

SPF is a DNS policy published by a domain. The receiver compares the connecting
server's IP address with the policy for the **envelope domain**. Given this SMTP
identity:

```text
MAIL FROM:<bounce@mailer.example>
```

the receiver might report:

```text
spf=pass smtp.mailfrom=mailer.example
```

**An SPF pass means:** the server was authorized to send for the envelope identity
SPF evaluated.

**An SPF pass does not mean:** the visible From address was authenticated, the
business is genuine, the content is honest, or a link is safe. An attacker can
configure SPF for `attacker.example` and still write:

```text
From: Microsoft Support <support@microsoft.com>
MAIL FROM:<bounces@attacker.example>
```

SPF can pass for `attacker.example`. Whether that supports the visible Microsoft
identity depends on DMARC alignment.

### DKIM: a domain signature

DKIM lets a domain sign selected headers and body content with a private key. The
receiver retrieves a public key from DNS and verifies the signature. A simplified
header is:

```text
DKIM-Signature: v=1; a=rsa-sha256; d=mailer.example; s=campaign;
  h=from:subject:date; bh=...; b=...
```

`d=mailer.example` is the signing domain. `s=campaign` is the selector, normally
used to find a public key at `campaign._domainkey.mailer.example`.

**A DKIM pass means:** the checked content has not changed since an entity able
to use the key for the `d=` domain signed it.

**A DKIM pass does not mean:** the `d=` domain matches the visible From domain,
the signer vouched for the claims, the account was not compromised, or the email
is safe. A phishing operator can sign mail from a domain they control.

### DMARC: alignment with the visible From domain

DMARC addresses the gap between reader-facing From and the domains SPF or DKIM
authenticated. It asks whether at least one *passing* SPF or DKIM identity is
**aligned** with the visible From domain.

For visible From `example-bank.dk`, aligned authentication normally uses
`example-bank.dk` or, with relaxed alignment, an allowed subdomain such as
`mail.example-bank.dk`. Strict alignment requires an exact match. The domain's
DMARC policy controls this detail.

This makes the following result intuitive:

```text
From: Example Bank <notice@example-bank.dk>
Return-Path: <bounce@mailer.example>
DKIM-Signature: d=mailer.example; s=campaign; ...
Authentication-Results: receiver.example;
  spf=pass smtp.mailfrom=mailer.example;
  dkim=pass header.d=mailer.example;
  dmarc=fail header.from=example-bank.dk
```

SPF and DKIM passed for `mailer.example`, but neither identity aligns with
`example-bank.dk`, so DMARC can fail.

**A DMARC pass means:** a receiver found passing SPF or DKIM evidence aligned
with the visible From domain.

**A DMARC pass does not mean:** the organization intended the message, the
account was not compromised, or the content and links are safe.

### How the mechanisms work together

Consider this suspicious-looking message:

```text
From: Skat Danmark <support@vespaiodesign.com>
Return-Path: <support@vespaiodesign.com>
DKIM-Signature: d=vespaiodesign.com; s=default; ...
Authentication-Results: receiver.example;
  spf=pass smtp.mailfrom=vespaiodesign.com;
  dkim=pass header.d=vespaiodesign.com;
  dmarc=none header.from=vespaiodesign.com
```

The authentication reasoning is:

```text
SPF pass for vespaiodesign.com
  ↓
The sending server was allowed to send for that envelope domain.

DKIM pass for vespaiodesign.com
  ↓
Selected content was signed for that domain.

DMARC none
  ↓
There is no DMARC policy/result protecting that actual From domain.

Separate identity question
  ↓
The display name claims Skat Danmark, while the observed domain is unrelated.
```

All those results can be technically consistent without establishing that the
sender represents Skattestyrelsen.

### How PhishGuard currently evaluates authentication

PhishGuard reads `spf=`, `dkim=`, and `dmarc=` values from
`Authentication-Results`. It does not independently perform DNS lookups, SPF
evaluation, DKIM signature verification, or DMARC alignment checks.

| Reported result | Current treatment |
| --- | --- |
| `pass` | No authentication risk signal |
| `fail`, `permerror`, `temperror` | High-severity signal |
| `softfail`, `neutral`, `none` | Medium-severity signal |
| Missing individual result | Medium-severity signal |
| Missing `Authentication-Results` header | Low-severity signal |

An arbitrary `.eml` file can contain a forged `Authentication-Results` header.
The result is most useful when a trusted receiving provider added it. Passing
authentication never subtracts from independent sender, link, or content evidence.

## 4. Sender Identity Analysis

Sender analysis separates claims from observed identities. Consider:

```text
From: MitID Kundeservice <security@account-check.example>
Reply-To: answers@support-desk.example
```

`MitID Kundeservice` is a display-name claim. `account-check.example` is the
actual From domain. `support-desk.example` is the reply destination. A human
analyst compares these with authentication and the requested action.

Display names are easy to control. A different Reply-To can be suspicious, but
it can also be normal for a ticket system, mailing list, or outsourced support.
Brand impersonation is more specific: a familiar organization name is claimed,
but the observed domain has no established relationship to it.

`Appleton Community Group` is not automatically an Apple claim because it
contains the same letters. Likewise, `skat.dk.attacker.example` is not a
Skattestyrelsen domain merely because a familiar name occurs early in the host.

### How PhishGuard currently evaluates sender identity

The sender analyzer uses configurable organization profiles containing a name,
display-name aliases, verified organization domains, optional country context,
and optional action-specific service domains. Defaults include Skattestyrelsen
(`Skat Danmark`, `Skattestyrelsen`, and `SKAT`, with `skat.dk` and `sktst.dk`)
plus selected other common organizations.

Only a complete configured alias in the **display name** establishes a profile
claim. A name in the body or local part of an address does not. A high-severity
signal is emitted when a claimed profile's From domain lies outside its configured
organization domains. A medium-severity signal is emitted when Reply-To belongs
to a different registrable domain.

Profiles are comparison evidence, not a catalogue of safe senders. They do not
prove a third-party account is legitimate, make unknown organizations suspicious,
or turn an ordinary external domain into phishing by itself.

## 5. URL and Link Analysis

### Reading a URL

Take this address:

```text
https://login.microsoft.com.security-check.example/account
```

| Part | Value | Meaning |
| --- | --- | --- |
| Scheme | `https` | Encrypts transport to the hostname reached. |
| Hostname | `login.microsoft.com.security-check.example` | The complete server name a browser contacts. |
| Registrable domain | `security-check.example` | The domain an independent registrant is likely to control. |
| Subdomains | `login.microsoft.com` | Labels chosen to look familiar. |
| Path | `/account` | A route; it does not establish ownership. |

The controlling clue is normally the registrable domain, not a familiar word at
the beginning. `microsoft.com.security-check.example` is under
`security-check.example`, not Microsoft.

The public suffix is the part below which independent parties can register names.
It is not always a single label: `.com`, `.co.uk`, and `.adv.br` are examples.
`zanuto.adv.br` and `different.adv.br` are separate registrable domains even
though both end in `.adv.br`.

HTTPS is useful: it encrypts traffic and validates a certificate for the hostname
reached. It does **not** prove the hostname is honest or belongs to the claimed
organization. A phishing site can use HTTPS.

### Interpreting links in context

The strongest link evidence often comes from contradiction:

```text
Visible label:     https://www.example-bank.dk
Actual href:       https://login-check.example/session
Requested action:  enter your security code
```

The label and destination disagree, and the action is sensitive. But an ordinary
marketing link can use a tracking redirect, so a mismatch alone remains weaker.

Login, payment, credential, and identity-verification links require more care.
An external target alone is not proof: sellers use payment processors, hotels use
regional booking sites, and identity providers can handle sign-in. The useful
question is whether there is an established relationship for *this action*.

Country suffixes are weak context only. A `.br` domain does not prove Brazilian
ownership or fraud; a Danish business can have a Brazilian partner. `.dk` and
`.com` provide no automatic safety credit.

### How PhishGuard currently evaluates links

PhishGuard uses each link's target, visible label, and local context. Link-context
rules recognize selected English and Danish phrases for identity verification,
login, credentials, and payments. They combine a sensitive action with the
claimed configured organization and destination.

- A displayed URL that differs from its target is medium evidence for an ordinary
  link because it may be a legitimate redirect. It is stronger for a sensitive
  action with no established relationship.
- A sensitive action is strong evidence when a known claimed organization has
  both an unrelated From domain and an unrelated destination.
- An unfamiliar external sensitive-action destination is low-strength evidence
  when no known organization claim exists; external services may be legitimate.

Profiles can specify verified service domains separately for `identity`, `login`,
`payment`, and `credentials`. A payment relationship does not automatically
justify a credential collection page. New relationships should be verified,
narrowly scoped, and tested with benign counterexamples.

The generic URL analyzer also identifies explicit HTTP links, action-looking host
names, known tracking/redirect hosts, and destinations outside the sender's
registrable domain. These are low-strength supporting signals because external
links are common in genuine email.

Hostnames are normalized with IDNA and compared using an offline Public Suffix
List snapshot, including listed private suffixes. PhishGuard does not download a
suffix list or visit URLs during analysis. Country context is considered only
after a recognized organization, sensitive action, and conflicting identity
evidence already exist; it contributes at most 2.5 points.

## 6. Content and Social-Engineering Analysis

Content analysis looks for persuasion techniques and requests that become risky
in context: urgency, threats of suspension, generic delivery notices, unexpected
refunds, requests for passwords or payment information, and calls to action.

None is inherently malicious. A real delivery service says “delivery,” a genuine
invoice says “payment,” and a password reset may request a sign-in. Evidence gets
stronger when categories reinforce each other:

```text
Urgency or threat
  + sensitive action
  + sender claim inconsistent with From domain
  + unexplained destination
  ↓
stronger phishing evidence
```

Obfuscation can also matter. Zero-width characters, soft hyphens, and unusual
combining marks can evade simple matching or disguise words, but can have benign
uses too.

### How PhishGuard currently evaluates content

The standalone content analyzer uses the subject and extracted visible text. It
currently supports selected **English** patterns for generic notifications without
expected identifiers, credential requests, urgency paired with an action, and
Unicode obfuscation. The separate link-context analyzer has selected Danish and
English action patterns. Neither is general language understanding.

Legitimate password resets, refunds, invoices, and delivery notices can use the
same wording. Other languages, image-only wording, novel phrasing, and legitimate
special cases remain limitations. A footer claiming a message is a “test” is not
verified evidence and does not bypass other rules.

## 7. Attachment Analysis

Attachment analysis is another part of phishing assessment. A human analyst may
inspect executable formats, double extensions such as `invoice.pdf.exe`, macro-
enabled Office files, HTML attachments, archives, password-protected archives,
misleading filenames, and whether the file makes sense for the stated message.

For example, an unexpected `Delivery-details.html` attachment can present a fake
login page. A `.pdf` extension alone does not establish safety. File type, source,
business context, and malware scanning all matter.

PhishGuard currently extracts attachment metadata but has **no attachment-risk
analyzer**. The reserved attachment score category is not a current capability.

## 8. Combining Evidence

Evidence from independent categories is usually more convincing than several
variants of one observation:

```text
Authentication ───┐
Sender identity ──┤
URL / links ──────┼──> combined evidence
Content ──────────┤
Attachments ──────┘
```

Consider this analysis:

```text
From: Skat Danmark <support@vespaiodesign.com>
Authentication-Results: spf=pass; dkim=pass; dmarc=none
Button: Bekræft med MitID
Destination: https://abcd.zanuto.adv.br/url/digital/
```

The reasoning is not “`.br` means phishing.” Rather:

1. SPF and DKIM establish infrastructure for `vespaiodesign.com`, not a right to
   represent Skattestyrelsen.
2. The display name claims Skattestyrelsen while the observed From domain is
   outside that profile's known domains.
3. The button asks for identity verification.
4. The destination has no configured relationship to that organization for this
   action.
5. The country suffix conflict is a small supporting clue after the stronger
   identity/action contradiction already exists.

A Danish travel business linking to a Brazilian hotel is a useful counterexample:
the external `.br` target can be normal when no claimed authority, sensitive
credential request, or identity contradiction exists.

PhishGuard groups related link findings. A generic external-link mismatch, host
keyword, and stronger contextual explanation for the same target do not all add
their full score. Repeated buttons also do not multiply the strongest contextual
or geographic contribution.

## 9. How PhishGuard Scores the Evidence

A signal has a reason, category, confidence, severity, and optional evidence
group. The reason explains the observation. Confidence is the rule's hand-chosen
strength from 0.0 to 1.0. Severity is descriptive; it is not a second numerical
multiplier. An evidence group identifies overlapping observations.

The basic contribution is:

```text
confidence × category weight × 100
```

| Category | Weight | Additional handling |
| --- | ---: | --- |
| Authentication | 0.25 | Additive signals |
| Sender | 0.20 | Additive signals |
| URL | 0.30 | Related destination evidence can be grouped |
| Content | 0.15 | Additive signals |
| Attachment | 0.10 | Reserved; no current analyzer |
| Link context | 0.50 | Strongest contribution only, up to 50 points |
| Geography | 0.05 | Strongest contribution only, capped at 2.5 points |

After grouping and caps, PhishGuard sums contributions, truncates to an integer,
and caps the result at 100.

| Score | Label |
| --- | --- |
| 0–20 | SAFE |
| 21–40 | LOW RISK |
| 41–60 | MEDIUM RISK |
| 61–80 | HIGH RISK |
| 81–100 | VERY HIGH RISK |

`SAFE` is a legacy label for the lowest band. It means the implemented rules
found few warnings, not that authenticity or safety was proven.

## 10. Reading a Complete PhishGuard Report

Read a report as an evidence-based argument rather than an instruction to trust
or distrust solely from a number. A complete interpretation could be:

```text
Authentication: DMARC returned none.
Sender: The display name claims Skattestyrelsen, but From is unrelated.
Link: The message requests identity verification at an unexplained target.
Content context: The surrounding text promises a concrete tax refund.
Attachment: No attachment-risk analysis is currently available.
Score: Very high risk.
```

Authentication alone is moderate evidence. The claimed identity and the sensitive
action destination are separate observations that reinforce it. The score helps
prioritize the message; the reasons explain why a person should avoid the link
and independently navigate to the organization's known website.

“Content context” in this example is a human interpretation, not necessarily a
standalone PhishGuard content signal: the current standalone content patterns are
English-only. This distinction matters when comparing a report with the broader
evidence an analyst can see.

Conversely, a report containing only “external link host does not match sender”
needs careful interpretation. Newsletters, payment providers, and social links
commonly create this weak signal. Look for corroborating evidence.

## 11. Current Limitations and Future Analysis

Email analysis can theoretically inspect much more than PhishGuard currently
does. Current limitations include:

- no URL fetching, redirect expansion, reputation lookup, or destination-page
  analysis;
- no independent SPF, DKIM, or DMARC verification and no trusted-header boundary;
- no browser rendering, JavaScript execution, OCR, or comprehensive Unicode
  confusable analysis;
- selected Danish/English link actions, English standalone content patterns, and
  a limited organization-profile catalogue;
- no attachment-risk analyzer, malware scanning, or archive inspection;
- no proof that a configured third-party domain represents a particular tenant or
  safe transaction; and
- hand-set rules, weights, and thresholds that require a broad labelled corpus
  before claiming measured accuracy or calibrated probability.

New rules should be evaluated with phishing cases and benign counterexamples:
legitimate payments, international correspondence, newsletters, password resets,
and notifications often share superficial characteristics with phishing. The aim
is explainable assistance: detect, warn, and let the person make the final choice.
