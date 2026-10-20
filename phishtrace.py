#!/usr/bin/env python3
"""
PhishTrace - a simple, repeatable phishing investigation workflow.

Pipeline (each step is one function below):
  1. PARSE    - work out whether the input is an email, a URL, or a plain message
  2. EXTRACT  - pull out indicators of compromise (IOCs): URLs, domains, IPs, emails, file hashes
  3. ANALYZE  - run simple, explainable checks on headers, URLs, text and attachments
  4. ENRICH   - look indicators up in an OFFLINE threat-intel list (we never touch live sites)
  5. SCORE    - add up points -> risk score -> verdict + confidence
  6. REPORT   - evidence table, ATT&CK mapping, containment + user guidance

Safety: this tool NEVER connects to any URL. It only reads text.
Usage:  python3 phishtrace.py samples/01_paypal_typosquat.eml
        python3 phishtrace.py samples/            (analyze a folder + find campaigns)
        python3 phishtrace.py --web               (small local web page)
"""
import argparse
import csv
import hashlib
import html
import ipaddress
import json
import re
import sys
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# Small lists the checks use. Edit these to tune the tool.
# --------------------------------------------------------------------------
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me", "mail.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = {"top", "xyz", "click", "buzz", "icu", "cfd", "sbs", "rest", "gq", "tk", "ml", "cf", "ga", "work", "zip", "loan"}
TWO_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "com.br", "co.jp"}
RISKY_EXT = {"exe", "scr", "js", "vbs", "bat", "lnk", "jar", "iso", "html", "htm", "docm", "xlsm"}
URGENCY = ["urgent", "immediately", "within 24 hours", "suspended", "final notice", "act now", "locked",
           "unusual activity", "verify your account", "will be closed", "limited access", "is held"]
CREDENTIALS = ["password", "log in", "login", "sign in", "verify your", "confirm your", "social security",
               "one-time code", "credit card", "bank details", "update your payment"]
MONEY = ["gift card", "wire transfer", "bitcoin", "overdue", "refund", "purchase cards"]
GENERIC_GREETING = ["dear customer", "dear user", "dear valued", "dear sir", "dear account holder"]
URL_PATH_WORDS = re.compile(r"(login|signin|verify|secure|account|update|confirm|password)", re.I)
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"})

ATTACK = {  # MITRE ATT&CK technique names
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1656": "Impersonation",
    "T1036.007": "Masquerading: Double File Extension",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1657": "Financial Theft",
    "T1078": "Valid Accounts (possible follow-on if credentials were entered)",
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def refang(text):
    """Sanitized samples are often 'defanged' (hxxp, [.]). Turn them back so we can parse them."""
    return re.sub(r"hxxp", "http", text, flags=re.I).replace("[.]", ".").replace("(.)", ".")


def defang(s):
    """Make an indicator safe to paste in a report/chat so nobody clicks it by accident."""
    return s.replace("http", "hxxp").replace(".", "[.]")


def registered_domain(host):
    """'login.paypal.com' -> 'paypal.com'. (Simple version; no public-suffix library needed.)"""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def lev(a, b):
    """Edit distance: how many single-letter changes turn a into b."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def load_brands():
    brands = {}
    with open(HERE / "intel" / "brands.csv", newline="") as f:
        for row in csv.DictReader(f):
            brands[row["brand"].lower()] = set(row["official_domains"].split(";"))
    return brands


def load_intel():
    """Offline threat-intel list (format mimics PhishTank/OpenPhish/URLhaus exports)."""
    intel = {}
    with open(HERE / "intel" / "known_bad.csv", newline="") as f:
        for row in csv.DictReader(f):
            intel[row["indicator"].lower()] = row
    return intel


BRANDS = load_brands()
INTEL = load_intel()
ALL_OFFICIAL = set().union(*BRANDS.values())


def brand_abuse(domain):
    """Does this registered domain pretend to be a known brand? -> (kind, brand) or None."""
    if domain in ALL_OFFICIAL:
        return None
    label = domain.split(".")[0]
    norm = label.lower().translate(LEET).replace("rn", "m").replace("vv", "w")
    tokens = norm.split("-")
    for brand in BRANDS:
        b = brand.replace(" ", "")
        if norm == b or (len(b) >= 5 and lev(norm, b) <= 1):
            return ("lookalike (typosquat) of", brand)
        if b in tokens or (len(b) >= 5 and norm.startswith(b)):
            return ("brand name inside unofficial domain:", brand)
    return None


def brand_in_text(text):
    low = text.lower()
    return [b for b in BRANDS if re.search(r"\b" + re.escape(b) + r"\b", low)]


class LinkParser(HTMLParser):
    """Collects (href, visible text) for every <a> tag, plus all visible text."""

    def __init__(self):
        super().__init__()
        self.links, self.text, self._href, self._buf = [], [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._buf = dict(attrs).get("href"), []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None


class Case:
    """Collects findings. Each finding = what we saw + how many risk points + proof."""

    def __init__(self):
        self.findings = {}

    def flag(self, category, name, points, evidence, attack=None):
        f = self.findings.setdefault(name, {"category": category, "name": name, "points": points,
                                            "evidence": [], "attack": attack or []})
        if evidence not in f["evidence"]:
            f["evidence"].append(evidence)


# --------------------------------------------------------------------------
# Step 1: PARSE
# --------------------------------------------------------------------------
def detect_kind(text):
    s = text.strip()
    if re.fullmatch(r"https?://\S+", s):
        return "url"
    head = s.split("\n\n")[0]
    if re.search(r"(?im)^from:\s", head) and re.search(r"(?im)^(subject|date|to|received|message-id):", head):
        return "email"
    return "message"


# --------------------------------------------------------------------------
# Step 3: ANALYZE - URL checks
# --------------------------------------------------------------------------
def check_url(case, url, link_text=None):
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        return
    if not host:
        return
    reg = host if is_ip(host) else registered_domain(host)
    tld = host.rsplit(".", 1)[-1]

    if is_ip(host):
        case.flag("url", "URL uses a raw IP address", 25, f"{defang(url)} -> host {host}", ["T1566.002"])
    if "@" in (p.netloc or ""):
        case.flag("url", "URL contains '@' trick (real host is after the @)", 25,
                  f"{defang(url)} -> real host is {defang(host)}", ["T1566.002"])
    if host.startswith("xn--") or ".xn--" in host or any(ord(c) > 127 for c in host):
        case.flag("url", "Punycode / non-ASCII domain (homograph risk)", 20, defang(host), ["T1656"])
    if host in SHORTENERS:
        case.flag("url", "Link shortener hides the real destination", 15, defang(url), ["T1566.002"])
    if tld in SUSPICIOUS_TLDS:
        case.flag("url", "Domain uses a TLD often abused for phishing", 10, f".{tld} in {defang(host)}")
    if p.scheme == "http":
        case.flag("url", "Link is not encrypted (http, not https)", 8, defang(url))
    if host.count(".") >= 4:
        case.flag("url", "Unusually many subdomains", 8, defang(host))
    if not is_ip(host) and reg.split(".")[0].count("-") >= 2:
        case.flag("url", "Domain name has several hyphens", 5, defang(reg))
    if URL_PATH_WORDS.search(p.path or "") or URL_PATH_WORDS.search(reg.split(".")[0]):
        case.flag("url", "Login/verify style words in link", 8, defang(url))
    if len(url) > 100:
        case.flag("url", "Very long URL", 5, f"{len(url)} characters")

    abuse = brand_abuse(reg)
    if abuse:
        case.flag("url", "Link domain imitates a known brand", 30, f"{defang(reg)} is a {abuse[0]} '{abuse[1]}'",
                  ["T1583.001", "T1656"])
    else:
        # brand name in a sub-domain or user-info of someone else's domain, e.g. paypal.com.evil.top
        pre = host[: -len(reg)] if host.endswith(reg) else host
        pre += " " + (p.username or "")
        for b, offs in BRANDS.items():
            if reg not in offs and re.search(re.escape(b), pre) :
                case.flag("url", "Brand name placed in sub-domain/user-info of another domain", 25,
                          f"'{b}' appears in {defang(host)} but registered domain is {defang(reg)}", ["T1656"])
                break

    if link_text:
        m = re.search(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", link_text.lower())
        if m and registered_domain(m.group(1)) != reg:
            case.flag("url", "Link text shows one site but link goes to another", 25,
                      f"text '{defang(link_text)}' -> actual {defang(url)}", ["T1566.002"])

    for key in (host, reg, url.lower()):
        hit = INTEL.get(key)
        if hit:
            case.flag("intel", "URL/domain found in threat-intel list", 40,
                      f"{defang(key)} -> {hit['source']}: {hit['note']}", ["T1566.002"])
            break


# --------------------------------------------------------------------------
# Steps 1-3: PARSE + EXTRACT + ANALYZE (the main function)
# --------------------------------------------------------------------------
def analyze(raw_text, name="sample"):
    text = refang(raw_text.replace("\r\n", "\n"))
    kind = detect_kind(text)
    case = Case()
    iocs = {"urls": [], "domains": [], "ips": [], "emails": [], "sender_domain": None, "attachments": []}
    links, body_text, subject, headers = [], text, "", {}

    # ---- email parsing --------------------------------------------------
    if kind == "email":
        msg = Parser(policy=policy.default).parsestr(text)
        subject = str(msg["Subject"] or "")
        body_text = ""
        for ctype in ("plain", "html"):
            part = msg.get_body((ctype,))
            if part is None:
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if ctype == "html":
                lp = LinkParser()
                lp.feed(content)
                links += lp.links
                content = " ".join(lp.text)
            body_text += " " + content
        body_text = subject + " " + body_text

        for part in msg.iter_attachments():
            fname = part.get_filename() or "unnamed"
            data = part.get_payload(decode=True) or b""
            iocs["attachments"].append({"name": fname, "sha256": hashlib.sha256(data).hexdigest()})

        # ---- header checks ---------------------------------------------
        from_name, from_addr = parseaddr(str(msg["From"] or ""))
        from_dom = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        iocs["sender_domain"] = registered_domain(from_dom) if from_dom else None
        iocs["emails"].append(from_addr)
        headers = {"From": str(msg["From"]), "Reply-To": str(msg["Reply-To"]), "Return-Path": str(msg["Return-Path"]),
                   "Subject": subject}

        _, reply_addr = parseaddr(str(msg["Reply-To"] or ""))
        if reply_addr:
            iocs["emails"].append(reply_addr)
            if registered_domain(reply_addr.split("@")[-1]) != iocs["sender_domain"]:
                case.flag("header", "Reply-To domain differs from From domain", 15,
                          f"From {defang(from_addr)} but replies go to {defang(reply_addr)}", ["T1656"])
        _, rp = parseaddr(str(msg["Return-Path"] or ""))
        if rp and "@" in rp and registered_domain(rp.split("@")[-1]) != iocs["sender_domain"]:
            case.flag("header", "Return-Path domain differs from From domain", 10,
                      f"From {defang(from_addr)} vs Return-Path {defang(rp)}")

        auth = " ".join(str(v) for k, v in msg.items() if k.lower() in ("authentication-results", "received-spf"))
        results = {k: (re.search(k + r"=(\w+)", auth, re.I) or [None, None])[1] for k in ("spf", "dkim", "dmarc")}
        results = {k: (v.lower() if v else None) for k, v in results.items()}
        pts = {"spf": 15, "dkim": 10, "dmarc": 15}
        for k, v in results.items():
            if v in ("fail", "permerror"):
                case.flag("header", f"{k.upper()} authentication failed", pts[k], f"{k}={v}")
            elif v == "softfail":
                case.flag("header", f"{k.upper()} soft-fail", 8, f"{k}={v}")
        if results["spf"] == results["dkim"] == results["dmarc"] == "pass" and from_dom not in FREE_MAIL:
            case.flag("mitigating", "SPF, DKIM and DMARC all pass", -15, "spf=dkim=dmarc=pass")
        headers["Auth"] = results

        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ".join(str(v) for v in msg.get_all("Received", []))):
            if is_ip(ip) and ip not in iocs["ips"]:
                iocs["ips"].append(ip)

        if from_dom:
            abuse = brand_abuse(registered_domain(from_dom))
            if abuse:
                case.flag("header", "Sender domain imitates a known brand", 25,
                          f"{defang(from_dom)} is a {abuse[0]} '{abuse[1]}'", ["T1656", "T1583.001"])
            for b in brand_in_text(from_name):
                if registered_domain(from_dom) not in BRANDS[b]:
                    case.flag("header", "Display name claims a brand the sender domain does not own", 20,
                              f"display name '{from_name}' but sending domain is {defang(from_dom)}", ["T1656"])
            if from_dom in FREE_MAIL and re.search(r"\b(ceo|cfo|director|president|manager|hr|payroll|it support|helpdesk)\b", from_name, re.I):
                case.flag("header", "Free-mail address used for an executive/authority display name", 20,
                          f"'{from_name}' sends from {defang(from_dom)}", ["T1656"])
            sd = registered_domain(from_dom)
            for key in (from_dom, sd, from_addr.lower()):
                if key in INTEL:
                    case.flag("intel", "Sender found in threat-intel list", 30,
                              f"{defang(key)} -> {INTEL[key]['source']}: {INTEL[key]['note']}", ["T1656"])
                    break

        # ---- attachment checks -----------------------------------------
        for a in iocs["attachments"]:
            ext = a["name"].lower().rsplit(".", 1)[-1] if "." in a["name"] else ""
            if ext in RISKY_EXT:
                case.flag("attachment", "Risky attachment type", 25,
                          f"{a['name']} (.{ext}) sha256={a['sha256'][:16]}...", ["T1566.001", "T1204.002"])
            if re.search(r"\.\w{2,4}\.(exe|scr|js|vbs|bat|lnk)$", a["name"].lower()):
                case.flag("attachment", "Double file extension disguises an executable", 15, a["name"], ["T1036.007"])

    # ---- extract URLs from visible text (all input kinds) ------------------
    seen_text = {h for h, _ in links} | {t for _, t in links if t}  # decoy link text is not a real destination
    for u in re.findall(r"https?://[^\s<>\"')\]]+", text):
        u = u.rstrip(".,;")
        if u not in seen_text:
            links.append((u, None))
            seen_text.add(u)

    # ---- URL checks + IOC lists ---------------------------------------------
    for href, label in links:
        if not href.lower().startswith("http"):
            continue
        if href not in iocs["urls"]:
            iocs["urls"].append(href)
        try:
            h = (urlparse(href).hostname or "").lower()
        except ValueError:
            continue
        if h:
            d = h if is_ip(h) else registered_domain(h)
            if is_ip(h) and h not in iocs["ips"]:
                iocs["ips"].append(h)
            if d not in iocs["domains"]:
                iocs["domains"].append(d)
        check_url(case, href, label)

    # ---- plain emails found in body text (not inside URLs) ----------------
    no_urls = re.sub(r"https?://\S+", " ", body_text)
    for e in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", no_urls):
        if e.lower() not in [x.lower() for x in iocs["emails"]]:
            iocs["emails"].append(e)

    for ip in iocs["ips"]:
        if ip in INTEL:
            case.flag("intel", "IP found in threat-intel list", 40, f"{ip} -> {INTEL[ip]['note']}")

    # ---- content checks ---------------------------------------------------
    low = body_text.lower()
    u = [w for w in URGENCY if w in low]
    c = [w for w in CREDENTIALS if w in low]
    m = [w for w in MONEY if w in low]
    g = [w for w in GENERIC_GREETING if w in low]
    if u:
        case.flag("content", "Urgency / threat language", min(5 * len(u), 15), "phrases: " + ", ".join(u))
    if c:
        case.flag("content", "Asks for credentials or sensitive data", min(5 * len(c), 10), "phrases: " + ", ".join(c),
                  ["T1598.003"] if iocs["urls"] else [])
    if m:
        case.flag("content", "Money / gift-card / payment request", min(5 * len(m), 10), "phrases: " + ", ".join(m), ["T1657"])
    if g:
        case.flag("content", "Generic greeting (not addressed to you)", 5, "phrases: " + ", ".join(g))
    if iocs["urls"]:
        brands = brand_in_text(body_text)
        for b in brands:
            if not any(registered_domain(urlparse(x).hostname or "") in BRANDS[b] for x in iocs["urls"]):
                case.flag("content", "Message names a brand but no link goes to that brand", 15,
                          f"mentions '{b}', links go to: " + ", ".join(defang(d) for d in iocs["domains"]), ["T1656"])
                break

    return build_result(name, kind, headers, iocs, case, subject)


# --------------------------------------------------------------------------
# Steps 5: SCORE + recommendations
# --------------------------------------------------------------------------
def build_result(name, kind, headers, iocs, case, subject):
    findings = sorted(case.findings.values(), key=lambda f: -f["points"])
    score = max(0, min(100, sum(f["points"] for f in findings)))
    verdict = "PHISHING" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LIKELY BENIGN"
    cats = {f["category"] for f in findings if f["points"] > 0}
    # Confidence is simple: far from a threshold, or several independent kinds of evidence, = more confident
    if verdict == "LIKELY BENIGN":
        confidence = "High" if score <= 10 else "Medium"
    elif verdict == "PHISHING":
        confidence = "High" if len(cats) >= 3 else "Medium"
    else:
        confidence = "Low" if len(cats) <= 2 else "Medium"

    attack = []
    if verdict != "LIKELY BENIGN":
        for f in findings:
            for t in f["attack"]:
                if t not in attack:
                    attack.append(t)
        if iocs["urls"] and "T1566.002" not in attack:
            attack.append("T1566.002")
        if "T1566.002" in attack and "T1204.001" not in attack:
            attack.append("T1204.001")
        if "T1598.003" in attack and "T1078" not in attack:
            attack.append("T1078")

    intel_hits = [f for f in findings if f["category"] == "intel"]
    return {"name": name, "kind": kind, "subject": subject, "headers": headers, "iocs": iocs, "findings": findings,
            "score": score, "verdict": verdict, "confidence": confidence, "intel_hits": intel_hits,
            "attack": [(t, ATTACK[t]) for t in attack], "actions": recommend(verdict, iocs, findings)}


def recommend(verdict, iocs, findings):
    names = " ".join(f["name"] for f in findings)
    if verdict == "LIKELY BENIGN":
        return {"containment": ["No containment needed. Keep the message for reference."],
                "user": ["Looks legitimate, but still type the website address yourself instead of clicking if you are unsure."]}
    contain = []
    if iocs["sender_domain"] and iocs["sender_domain"] not in FREE_MAIL:
        contain.append(f"Block sender domain {defang(iocs['sender_domain'])} at the email gateway.")
    if iocs["domains"]:
        contain.append("Block these domains/IPs at DNS and web proxy: " + ", ".join(defang(d) for d in iocs["domains"]) + ".")
    contain += ["Search all mailboxes for the same sender, subject or links, and remove copies (purge).",
                "Check proxy/DNS logs to see who clicked or visited the links.",
                "For anyone who clicked or entered a password: reset the password, revoke active sessions, check mailbox "
                "forwarding rules, and make sure MFA is on.",
                "Add the IOCs to your watch-list / SIEM and keep the original email as evidence."]
    if iocs["attachments"]:
        contain.append("If an attachment was opened: isolate that device, run an antivirus/EDR scan, and submit the "
                       "file hash to your malware-analysis team.")
    if "Money" in names:
        contain.append("Finance team: do NOT send payments or gift cards; confirm the request by phoning the real person.")
    contain.append("Report it to your security team; public reporting options include the provider's abuse desk and "
                   "APWG (reportphishing@apwg.org).")
    user = ["Do not click links, open attachments or reply to this message.",
            "If you already entered a password, change it right away and tell IT/security.",
            "If you are unsure, go to the company's website by typing the address yourself, or call a known number.",
            "Use your 'Report phishing' button, then delete the message."]
    if verdict == "SUSPICIOUS":
        contain.insert(0, "Treat as suspicious: hold the message for analyst review before releasing it.")
    return {"containment": contain, "user": user}


# --------------------------------------------------------------------------
# Campaign correlation: group flagged cases that share infrastructure
# --------------------------------------------------------------------------
def cluster(results):
    flagged = [r for r in results if r["verdict"] != "LIKELY BENIGN"]
    parent = list(range(len(flagged)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner = {}
    for i, r in enumerate(flagged):
        keys = set(r["iocs"]["domains"]) | set(r["iocs"]["ips"])
        if r["iocs"]["sender_domain"]:
            keys.add(r["iocs"]["sender_domain"])
        for k in keys - FREE_MAIL - ALL_OFFICIAL - SHORTENERS:
            if k in owner:
                parent[find(i)] = find(owner[k])
            else:
                owner[k] = i
    groups = {}
    for i, r in enumerate(flagged):
        groups.setdefault(find(i), []).append(r)
    out = []
    for g in groups.values():
        if len(g) > 1:
            shared = set.intersection(*[set(x["iocs"]["domains"]) | {x["iocs"]["sender_domain"]} for x in g]) \
                if all(x["iocs"]["domains"] for x in g) else set()
            out.append({"cases": [x["name"] for x in g], "shared": sorted(s for s in shared if s)})
    return out


# --------------------------------------------------------------------------
# Step 6: REPORT (markdown for terminal, HTML for browser)
# --------------------------------------------------------------------------
def render_markdown(r):
    L = [f"# PhishTrace Investigation: {r['name']}", "",
         f"**Verdict:** {r['verdict']}   |   **Risk score:** {r['score']}/100   |   **Confidence:** {r['confidence']}",
         f"**Input type:** {r['kind']}" + (f"   |   **Subject:** {r['subject']}" if r["subject"] else ""), ""]
    top = [f["name"] for f in r["findings"] if f["points"] > 0][:3]
    L += ["## Why", ("Top reasons: " + "; ".join(top) + ".") if top else "No suspicious indicators found.", ""]
    L += ["## Evidence (every point of risk is backed by something we saw)"]
    for f in r["findings"]:
        L.append(f"- [{f['category']}] **{f['name']}** ({f['points']:+d})")
        for e in f["evidence"]:
            L.append(f"    - {e}")
    i = r["iocs"]
    L += ["", "## Indicators of Compromise (defanged = safe to share)"]
    L += [f"- URL: {defang(u)}" for u in i["urls"]] + [f"- Domain: {defang(d)}" for d in i["domains"] if not is_ip(d)]
    L += [f"- IP: {defang(x)}" for x in i["ips"]] + [f"- Email: {e.replace('@', '[@]').replace('.', '[.]')}" for e in i["emails"]]
    L += [f"- Attachment: {a['name']}  sha256={a['sha256']}" for a in i["attachments"]]
    if not any([i["urls"], i["ips"], i["emails"], i["attachments"]]):
        L.append("- (none found)")
    L += ["", "## Threat-intelligence matches (offline list)"]
    L += [f"- {f['evidence'][0]}" for f in r["intel_hits"]] or ["- No matches."]
    L += ["", "## MITRE ATT&CK mapping"]
    L += [f"- {t}: {n}" for t, n in r["attack"]] or ["- Not applicable."]
    L += ["", "## Recommended containment"] + [f"- {a}" for a in r["actions"]["containment"]]
    L += ["", "## Guidance for the user"] + [f"- {a}" for a in r["actions"]["user"]]
    L += ["", "_Limits: rule-based and offline. Check results with a human analyst; never open links to 'confirm'._", ""]
    return "\n".join(L)


def render_html(r):
    e = html.escape
    color = {"PHISHING": "#c0392b", "SUSPICIOUS": "#d68910", "LIKELY BENIGN": "#1e8449"}[r["verdict"]]
    rows = "".join(
        f"<tr><td>{e(f['category'])}</td><td><b>{e(f['name'])}</b><br><small>{'<br>'.join(e(x) for x in f['evidence'])}</small></td>"
        f"<td>{f['points']:+d}</td></tr>" for f in r["findings"]) or "<tr><td colspan=3>Nothing suspicious found</td></tr>"
    i = r["iocs"]
    ioc = [("URL", defang(u)) for u in i["urls"]] + [("Domain", defang(d)) for d in i["domains"] if not is_ip(d)] + \
          [("IP", defang(x)) for x in i["ips"]] + [("Email", x.replace("@", "[@]").replace(".", "[.]")) for x in i["emails"]] + \
          [("File", f"{a['name']} sha256={a['sha256']}") for a in i["attachments"]]
    ioc_html = "".join(f"<li><b>{t}:</b> <code>{e(v)}</code></li>" for t, v in ioc) or "<li>none</li>"
    att = "".join(f"<li>{e(t)} - {e(n)}</li>" for t, n in r["attack"]) or "<li>n/a</li>"
    ul = lambda xs: "".join(f"<li>{e(x)}</li>" for x in xs)
    return f"""<html><head><meta charset=utf-8><title>PhishTrace report</title><style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2em auto;padding:0 1em;color:#222}}
.badge{{background:{color};color:#fff;padding:.4em .9em;border-radius:6px;font-weight:bold}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:6px;vertical-align:top}}
code{{background:#f3f3f3;padding:1px 4px}}</style></head><body>
<h1>PhishTrace: {e(r['name'])}</h1>
<p><span class=badge>{r['verdict']}</span> &nbsp; Risk <b>{r['score']}/100</b> &nbsp; Confidence <b>{r['confidence']}</b> &nbsp; Input: {r['kind']}</p>
<h2>Evidence</h2><table><tr><th>Type</th><th>Finding &amp; proof</th><th>Points</th></tr>{rows}</table>
<h2>IOCs (defanged)</h2><ul>{ioc_html}</ul>
<h2>ATT&amp;CK</h2><ul>{att}</ul>
<h2>Containment</h2><ul>{ul(r['actions']['containment'])}</ul>
<h2>User guidance</h2><ul>{ul(r['actions']['user'])}</ul></body></html>"""


# --------------------------------------------------------------------------
# Tiny local web page (paste a sample, get a report)
# --------------------------------------------------------------------------
def serve(port=8000):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs

    page = ("<html><body style='font-family:system-ui;max-width:900px;margin:2em auto'>"
            "<h1>PhishTrace</h1><p>Paste a <b>sanitized</b> email (with headers), a URL, or a message. "
            "Nothing is opened or sent anywhere.</p><form method=post>"
            "<textarea name=sample rows=20 style='width:100%'></textarea><br><br>"
            "<button style='padding:.6em 1.4em;font-size:1em'>Investigate</button></form></body></html>")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, body):
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._send(page)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            sample = parse_qs(self.rfile.read(n).decode("utf-8", "replace")).get("sample", [""])[0]
            self._send(render_html(analyze(sample, "pasted sample")) + "<p><a href='/'>&larr; Analyze another</a></p>")

        def log_message(self, *a):
            pass

    print(f"PhishTrace running at http://127.0.0.1:{port}  (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()


def main():
    ap = argparse.ArgumentParser(description="PhishTrace - phishing investigation workflow")
    ap.add_argument("path", nargs="?", help="a sample file, or a folder of samples")
    ap.add_argument("--html", metavar="OUT", help="also save an HTML report (file, or folder if input is a folder)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a report")
    ap.add_argument("--web", action="store_true", help="start the local web page")
    a = ap.parse_args()
    if a.web:
        return serve()
    if not a.path:
        ap.print_help()
        return
    p = Path(a.path)
    files = sorted(f for f in p.iterdir() if f.is_file() and f.suffix in (".eml", ".txt")) if p.is_dir() else [p]
    results = []
    for f in files:
        r = analyze(f.read_text(errors="replace"), f.name)
        results.append(r)
        if a.json:
            continue
        if p.is_dir():
            print(f"{f.name:40} {r['verdict']:14} score={r['score']:3}  confidence={r['confidence']}")
        else:
            print(render_markdown(r))
        if a.html:
            out = Path(a.html)
            if p.is_dir():
                out.mkdir(exist_ok=True)
                out = out / (f.stem + ".html")
            out.write_text(render_html(r))
    if a.json:
        print(json.dumps(results if p.is_dir() else results[0], indent=2))
    elif p.is_dir():
        print("\nCampaign correlation (flagged cases sharing infrastructure):")
        groups = cluster(results)
        for n, g in enumerate(groups, 1):
            print(f"  Campaign {n}: {', '.join(g['cases'])}  shared: {', '.join(defang(s) for s in g['shared']) or 'linked indirectly'}")
        if not groups:
            print("  none found")


if __name__ == "__main__":
    main()
