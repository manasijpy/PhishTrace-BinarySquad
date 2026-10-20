# PhishTrace (Streamlit edition) - beginner-friendly phishing investigation workflow

Paste, upload or pick a **sanitized** email (.eml), URL or text message and get a structured investigation:
indicators (IOCs), evidence, offline threat-intel matches, MITRE ATT&CK mapping, risk score, containment steps
and user guidance, in a clean web app. **It never opens or contacts any link.** It only reads text.

## Run the app (3 steps)
    python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
    pip install -r requirements.txt                          # installs Streamlit
    streamlit run app.py                                     # opens http://localhost:8501

Two pages (left sidebar):
- **Investigate** - pick a built-in sample, paste text, or upload a file; press *Investigate*. Tabs show Evidence,
  IOCs, Threat intel & ATT&CK, What to do, and the full report (download as Markdown / HTML / JSON; IOCs as CSV).
- **Test suite & campaigns** - runs all 18 samples against `samples/expected.csv`, shows precision / recall /
  false-positive rate / IOC accuracy, and groups flagged emails that share infrastructure into campaigns.

Not using Streamlit? The same engine still works from the terminal (no installs needed):
    python3 phishtrace.py samples/01_paypal_typosquat.eml
    python3 phishtrace.py samples/
    python3 tests/run_tests.py

## How the code is organised
- `phishtrace.py` - the investigation engine (parse -> extract -> analyze -> enrich -> score -> report). No Streamlit inside.
- `app.py` - the Streamlit screen. It only collects a sample, calls `analyze()`, and displays the result.
- `intel/` - `known_bad.csv` (offline threat intel) and `brands.csv` (brands to protect). Edit these freely.
- `samples/` - 18 fictional test cases + `expected.csv` answer key.  `tests/run_tests.py` - terminal accuracy check.

## The workflow (same steps every time)
1. **Parse** - email, URL or message?
2. **Extract** - URLs, domains, IPs, email addresses, attachment hashes
3. **Analyze** - checks on headers (SPF/DKIM/DMARC, Reply-To), URLs (typosquats, IP hosts, `@` trick, shorteners,
   mismatched link text), text (urgency, credential requests, money) and attachments (double extension, risky types)
4. **Enrich** - match against `intel/known_bad.csv` (offline; same idea as PhishTank/OpenPhish/URLhaus lists)
5. **Score** - each finding adds points: 60+ = PHISHING, 30-59 = SUSPICIOUS, below 30 = LIKELY BENIGN
6. **Report** - evidence for every point, ATT&CK techniques, containment steps, advice for the user

## Make it yours
- Add bad indicators: edit `intel/known_bad.csv` (paste rows from a real feed, same columns).
- Add brands to protect: edit `intel/brands.csv`.
- Change points / word lists: top of `phishtrace.py`.
- Add test cases: drop a file in `samples/` and a row in `samples/expected.csv`.

## Safety / ethics
All samples are fictional and sanitized (reserved or made-up domains, TEST-NET IPs, dummy attachment bytes).
Do not paste real credentials. Do not visit links from real phishing emails.
