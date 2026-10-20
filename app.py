"""
PhishTrace - Streamlit web app.

Run:  streamlit run app.py

All the investigation logic lives in phishtrace.py (no Streamlit in there).
This file is only the screen: it collects a sample, calls analyze(), and shows the result.
The app never opens or contacts any link; it only reads text.
"""
import csv
import json
from pathlib import Path

import streamlit as st

from phishtrace import analyze, cluster, defang, is_ip, render_html, render_markdown

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / "samples"
VERDICT_LABEL = {"PHISHING": "phishing", "SUSPICIOUS": "suspicious", "LIKELY BENIGN": "benign"}

st.set_page_config(page_title="PhishTrace", page_icon="🎣", layout="wide")


# ---------------------------------------------------------------- helpers
def sample_files():
    return sorted(f.name for f in SAMPLES.iterdir() if f.suffix in (".eml", ".txt"))


def show_verdict(r):
    """Big colored banner + three numbers."""
    msg = f"**{r['verdict']}**  -  risk score {r['score']}/100  -  confidence {r['confidence']}"
    if r["verdict"] == "PHISHING":
        st.error(msg, icon="🚨")
    elif r["verdict"] == "SUSPICIOUS":
        st.warning(msg, icon="⚠️")
    else:
        st.success(msg, icon="✅")
    st.progress(r["score"] / 100)
    c1, c2, c3 = st.columns(3)
    c1.metric("Risk score", f"{r['score']}/100")
    c2.metric("Evidence items", sum(1 for f in r["findings"] if f["points"] > 0))
    c3.metric("IOCs found", len(r["iocs"]["urls"]) + len(r["iocs"]["emails"]) + len(r["iocs"]["attachments"]))


def ioc_rows(r):
    i = r["iocs"]
    rows = [{"type": "URL", "indicator": defang(u)} for u in i["urls"]]
    rows += [{"type": "Domain", "indicator": defang(d)} for d in i["domains"] if not is_ip(d)]
    rows += [{"type": "IP", "indicator": defang(x)} for x in i["ips"]]
    rows += [{"type": "Email", "indicator": e.replace("@", "[@]").replace(".", "[.]")} for e in i["emails"]]
    rows += [{"type": "File", "indicator": f"{a['name']}  sha256={a['sha256']}"} for a in i["attachments"]]
    return rows


def show_report(r):
    show_verdict(r)
    tab_ev, tab_ioc, tab_ti, tab_act, tab_raw = st.tabs(
        ["🔎 Evidence", "🧷 IOCs", "🛰️ Threat intel & ATT&CK", "🛠️ What to do", "📄 Full report"])

    with tab_ev:
        st.caption("Every point of risk is backed by something the tool actually saw. Negative points reduce the risk.")
        if r["findings"]:
            st.dataframe([{"type": f["category"], "finding": f["name"], "points": f["points"],
                           "evidence": "  |  ".join(f["evidence"])} for f in r["findings"]],
                         hide_index=True)
            by_type = {}
            for f in r["findings"]:
                by_type[f["category"]] = by_type.get(f["category"], 0) + f["points"]
            st.markdown("**Points by evidence type**")
            st.bar_chart(by_type)
        else:
            st.info("No suspicious indicators found.")

    with tab_ioc:
        st.caption("Defanged (hxxp, [.]) so they are safe to copy into tickets and chats.")
        rows = ioc_rows(r)
        if rows:
            st.dataframe(rows, hide_index=True)
            buf = "type,indicator\n" + "\n".join(f'{x["type"]},"{x["indicator"]}"' for x in rows)
            st.download_button("⬇️ Download IOCs (CSV)", buf, file_name="iocs.csv", mime="text/csv")
        else:
            st.info("No indicators extracted.")
        if r["headers"]:
            with st.expander("Email headers used"):
                st.json({k: str(v) for k, v in r["headers"].items()})

    with tab_ti:
        st.markdown("**Offline threat-intelligence matches**")
        if r["intel_hits"]:
            for f in r["intel_hits"]:
                for e in f["evidence"]:
                    st.error(e)
        else:
            st.write("No matches in the offline list (`intel/known_bad.csv`).")
        st.markdown("**MITRE ATT&CK techniques**")
        if r["attack"]:
            st.dataframe([{"technique": t, "name": n} for t, n in r["attack"]],
                         hide_index=True)
        else:
            st.write("Not applicable for this verdict.")

    with tab_act:
        left, right = st.columns(2)
        with left:
            st.subheader("Containment (for the security team)")
            for a in r["actions"]["containment"]:
                st.markdown(f"- {a}")
        with right:
            st.subheader("Guidance (for the user)")
            for a in r["actions"]["user"]:
                st.markdown(f"- {a}")

    with tab_raw:
        md = render_markdown(r)
        st.markdown(md)
        d1, d2, d3 = st.columns(3)
        d1.download_button("⬇️ Report (Markdown)", md, file_name="phishtrace_report.md", mime="text/markdown")
        d2.download_button("⬇️ Report (HTML)", render_html(r), file_name="phishtrace_report.html", mime="text/html")
        d3.download_button("⬇️ Raw data (JSON)", json.dumps(r, indent=2), file_name="phishtrace_report.json",
                           mime="application/json")


# ---------------------------------------------------------------- page 1
def page_investigate():
    st.title("🎣 PhishTrace")
    st.write("Turn a suspicious email, URL or message into a structured investigation: "
             "indicators, evidence, risk score and next steps.")
    st.info("Safe by design: the tool only **reads text**. It never opens or contacts any link. "
            "Use sanitized or fictional samples only.", icon="🛡️")

    mode = st.sidebar.radio("How do you want to provide the sample?", ["Pick a built-in sample", "Paste text", "Upload a file"])
    text, name = "", "sample"

    if mode == "Pick a built-in sample":
        files = sample_files()
        name = st.sidebar.selectbox("Sample", files) if files else ""
        if name:
            text = (SAMPLES / name).read_text(errors="replace")
    elif mode == "Paste text":
        name = "pasted sample"
        text = st.text_area("Paste a sanitized email (with headers), a URL, or a message", height=260,
                            placeholder="From: ...\nSubject: ...\n\nBody...   or   http://example.test/login")
    else:
        up = st.file_uploader("Upload a .eml or .txt file", type=["eml", "txt"])
        if up is not None:
            name, text = up.name, up.getvalue().decode("utf-8", "replace")

    if text:
        with st.expander("Show the raw sample", expanded=False):
            st.code(text, language="text")

    if st.button("🔍 Investigate", type="primary", disabled=not text.strip()):
        st.session_state["result"] = analyze(text, name)

    if "result" in st.session_state:
        st.divider()
        st.subheader(f"Result: {st.session_state['result']['name']}")
        show_report(st.session_state["result"])
    elif not text.strip():
        st.caption("Choose or paste a sample, then press **Investigate**.")


# ---------------------------------------------------------------- page 2
def page_batch():
    st.title("🧪 Test suite & campaigns")
    st.write("Run PhishTrace on every sample and compare it with the answer key (`samples/expected.csv`).")
    key_file = SAMPLES / "expected.csv"
    if not key_file.exists():
        st.warning("samples/expected.csv not found.")
        return

    if st.button("▶️ Run all samples", type="primary"):
        rows = list(csv.DictReader(open(key_file)))
        results, table = [], []
        tp = fp = fn = tn = ioc_ok = exact = 0
        for row in rows:
            r = analyze((SAMPLES / row["file"]).read_text(errors="replace"), row["file"])
            results.append(r)
            got = VERDICT_LABEL[r["verdict"]]
            exact += got == row["truth"]
            t_pos, g_pos = row["truth"] != "benign", got != "benign"
            tp += t_pos and g_pos
            fp += (not t_pos) and g_pos
            fn += t_pos and (not g_pos)
            tn += (not t_pos) and (not g_pos)
            expected = set(filter(None, row["expected_url_domains"].split(";")))
            ioc_ok += expected == set(r["iocs"]["domains"])
            table.append({"sample": row["file"], "truth": row["truth"], "verdict": got, "score": r["score"],
                          "result": "✅ pass" if got == row["truth"] else "❌ fail"})
        n = len(rows)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        st.session_state["batch"] = {
            "table": table, "n": n, "exact": exact, "prec": prec, "rec": rec, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else 0.0, "ioc": ioc_ok, "groups": cluster(results)}

    b = st.session_state.get("batch")
    if not b:
        st.caption("Press **Run all samples** to see accuracy and campaign grouping.")
        return
    c = st.columns(5)
    c[0].metric("Exact verdicts", f"{b['exact']}/{b['n']}")
    c[1].metric("Precision", f"{b['prec']:.2f}")
    c[2].metric("Recall", f"{b['rec']:.2f}")
    c[3].metric("False-positive rate", f"{b['fpr']:.2f}")
    c[4].metric("IOC extraction", f"{b['ioc']}/{b['n']}")
    st.caption("Flagged = phishing or suspicious. These samples were written by the same author as the rules, "
               "so treat the numbers as a workflow check, not real-world accuracy.")
    st.dataframe(b["table"], hide_index=True)

    st.subheader("Campaign correlation")
    st.caption("Flagged cases that share a domain are grouped as one likely campaign.")
    if b["groups"]:
        for i, g in enumerate(b["groups"], 1):
            st.markdown(f"**Campaign {i}** - shared infrastructure: "
                        f"`{', '.join(defang(s) for s in g['shared']) or 'linked indirectly'}`")
            for case in g["cases"]:
                st.markdown(f"- {case}")
    else:
        st.write("No campaigns found.")


# ---------------------------------------------------------------- router
page = st.sidebar.radio("Page", ["Investigate", "Test suite & campaigns"], key="page")
st.sidebar.divider()
if page == "Investigate":
    page_investigate()
else:
    page_batch()
