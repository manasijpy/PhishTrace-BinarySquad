# PhishTrace - Short Technical Report

## Problem
Analysts get suspicious emails/URLs/messages and must decide if they are malicious, extract IOCs, understand the
attack path and explain the risk. A bare yes/no classifier does not give evidence or next steps.

## Approach
A rule-based, explainable pipeline (Parse -> Extract -> Analyze -> Enrich -> Score -> Report). Every risk point is tied
to a named finding and the exact evidence that triggered it, so an analyst can verify or overrule it.
No ML was used: rules are transparent, need no training data, and work offline. AI is optional per the brief.

## Checks implemented
| Area | Checks |
|---|---|
| Email headers | SPF/DKIM/DMARC fail or soft-fail; Reply-To and Return-Path mismatch; display-name brand/executive impersonation; free-mail sender; lookalike sender domain; all-pass mitigation |
| URLs | raw IP host; `@` trick; punycode; shortener; abused TLD; http; many subdomains/hyphens; login-style words; brand typosquat (leet-speak + edit distance); brand in sub-domain; link text vs real target mismatch |
| Content | urgency, credential requests, money/gift cards, generic greeting, brand named but links elsewhere |
| Attachments | risky types (.exe, .html, .docm ...), double extensions, SHA-256 |
| Intel | offline list lookup for URL, domain, sender, IP |

## Scoring
Points are summed (0-100). 60+ PHISHING, 30-59 SUSPICIOUS, <30 LIKELY BENIGN. Confidence rises with the number of
independent evidence types (header / URL / content / attachment / intel). Findings map to MITRE ATT&CK
(T1566.001/.002, T1598.003, T1204, T1656, T1583.001, T1036.007, T1657, T1078).

## Results (18 test cases: 12 phishing, 2 suspicious, 4 legitimate)
Run `python3 tests/run_tests.py`. Current output: 18/18 exact verdicts; precision 1.00, recall 1.00, F1 1.00,
false-positive rate 0.00; IOC URL-domain extraction 18/18. Campaign correlation groups 2 campaigns
(PayPal lookalike, Microsoft lookalike) by shared domains.

**Honest caveat:** the samples were written by the same author as the rules, so these numbers show the workflow works,
not how it would perform on real mail. Next step: evaluate on public datasets (e.g. Nazario corpus, PhishTank/OpenPhish
URL lists) and tune weights; expect false positives on legit brand-like domains (e.g. "applebees.com").

## Limitations
Rule-based and offline; no live DNS/WHOIS/domain-age lookups (deliberately, to avoid touching infrastructure); simple
registered-domain logic (no full public-suffix list); no attachment content analysis; no image/QR-code analysis;
Received-chain analysis is limited to IP extraction.

## Ideas for improvement
Domain-age and WHOIS enrichment (via approved feeds), QR-code decoding, ML text classifier as one extra signal,
fuzzy similarity of message bodies for campaign clustering, analyst dashboard.

## Ethics
Only fictional/sanitized samples. The tool never fetches links, and reports defang IOCs (hxxp, [.]) so they are safe to share.
