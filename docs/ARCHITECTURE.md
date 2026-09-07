# PhishGuard Architecture

PhishGuard analyzes raw email locally and produces explainable, deterministic
phishing-risk scores. It reports findings; it does not automatically delete mail.

## Current Processing Flow

```text
CLI reads raw MIME bytes
        ↓
MimeParser: decoded headers, both body alternatives, structured links
        ↓
EmailMessage
        ↓
Authentication / sender / URL / content analyzers
        ↓
DetectionSignals with reasons and optional evidence groups
        ↓
RiskScorer: weighted contributions, grouping, category caps
        ↓
AnalysisResult: score, risk band, reasons
```

The scorer currently invokes analyzers sequentially. Provider retrieval, an HTTP
analysis API, and a Firefox extension remain future integrations.

## Module Responsibilities

| Module | Responsibility |
| --- | --- |
| `mail/models.py` | Canonical headers, body, attachment, message, and structured-link models |
| `mail/parser.py` | MIME/charset/header decoding, visible text, link labels and local context |
| `mail/html_parser.py` | Local HTML text extraction and bounded anchor context |
| `providers/base.py` | Future provider adapter interface |
| `analyzers/base.py` | Analyzer interface and detection signals |
| `analyzers/authentication.py` | Interpret reported authentication-header outcomes |
| `analyzers/sender.py` | Configured organization claims and sender/address consistency |
| `analyzers/url.py` | Link actions, displayed destinations, domain relationships, URL patterns |
| `analyzers/link_context.py` | Sensitive action patterns and identity/destination combinations |
| `analyzers/domains.py` | Offline PSL boundaries, host normalization, and explicit domain matching |
| `analyzers/organizations.py` | Shared organization aliases, domains, countries, and scoped service relationships |
| `analyzers/content.py` | Selected English content patterns and Unicode obfuscation |
| `scoring/scorer.py` | Combine evidence without repeatedly counting grouped link findings |
| `scoring/signals.py` | Analysis results, reasons, and risk-band labels |
| `cli.py` | Read `.eml` files, invoke analyzers, and display results |

Parsing remains independent of analyzer and scoring policy. The existing list of
URL strings is retained alongside structured links so callers can migrate without
losing basic link extraction. Both MIME alternatives contribute analysis text.

## Domain and Organization Context

Domain comparisons use an offline `tldextract` instance backed by its bundled
Public Suffix List, with private suffixes enabled and runtime fetching/caching
disabled. Registrable domains are compared for ordinary host relationships;
configured service domains use explicit host boundaries. A domain containing a
brand's name is not evidence that the brand owns it.

Sender and URL analyzers share optional `OrganizationProfile` configuration. A
profile can name organization aliases, sender domains, expected country suffixes,
and verified third-party service domains scoped to an action. The CLI uses default
profiles; Python callers can supply the same custom set to both analyzers.

This configuration supports context without requiring every destination to match
the sender's name. A sensitive action at an unexplained destination is evaluated
with the claimed identity. Country suffixes add only weak, capped evidence after
the required contextual conditions hold; language alone never sets a country
expectation, and `.dk`/`.com` provide no safety credit.

## Scoring Policy

Each contribution starts with `confidence × category weight × 100`. Confidence
and weights are hand-set heuristics; severity is a descriptive label.

| Category | Weight | Cap/handling |
| --- | ---: | --- |
| Authentication | 0.25 | Additive |
| Sender | 0.20 | Additive |
| URL | 0.30 | Related link evidence grouped |
| Content | 0.15 | Additive |
| Attachment | 0.10 | Reserved; no analyzer yet |
| Link context | 0.50 | Strongest contribution, at most 50 points |
| Geography | 0.05 | Strongest contribution, at most 2.5 points |

Signals in the same evidence group count only their strongest contribution.
Category handling then limits repeated link-context and geographic evidence. The
final sum is truncated and capped at 100. This is not a calibrated probability;
the existing lowest-band `SAFE` label does not certify legitimacy.

Passing authentication never subtracts from other evidence. Recognized service
infrastructure does not disable contextual link checks. Profiles describe domain
relationships, not the trustworthiness of every tenant or transaction.

## Operational Limits

Analysis performs no URL requests, redirect following, image loading, or live DNS
authentication checks. Supplied authentication headers are not independently
verified. HTML extraction is not browser rendering or OCR. Link-action matching
supports selected Danish and English phrases; standalone content patterns remain
English. Organization coverage depends on configuration. Attachment metadata is
parsed but not risk-scored.

## Development Phases

1. Complete: repository setup, email models, MIME parsing, and the four analyzers.
2. Ongoing: rule coverage, false-positive regression tests, and score evaluation.
3. Planned: IMAP provider, analysis API, Microsoft Graph, and Firefox extension.
4. Later: background scanning and user-controlled quarantine.

See [EMAIL_ANALYSIS_GUIDE.md](EMAIL_ANALYSIS_GUIDE.md) for configuration examples and
[LOCAL_TESTING.md](LOCAL_TESTING.md) for validation guidance.
