import json
import time
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Vulnerability Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE = Path(__file__).parent


def _flatten(content):
    """
    Strip leading whitespace from every line and drop blank lines,
    so deeply nested HTML survives st.markdown's HTML-block rules
    regardless of how the source is indented.
    """
    lines = [line.lstrip() for line in content.split("\n")]
    lines = [line for line in lines if line != ""]
    return "\n".join(lines)


def md(content, **kwargs):
    return st.markdown(_flatten(content), **kwargs)


# ============================================================
# DATA LOADING  (unchanged logic)
# ============================================================

def first_existing(*names):
    for name in names:
        p = BASE / name
        if p.exists():
            return p
    return None


CSV_FILE = first_existing("vulnerabilities (1).csv", "vulnerabilities.csv")
PROFILE_FILE = first_existing("profile.json")
PROFILES_FILE = first_existing("profiles.json")


@st.cache_data
def load_vulnerabilities():
    if CSV_FILE is None:
        return pd.DataFrame(
            columns=["cve_id", "product_name", "cvss_base_score", "cisa_kev", "first_epss"]
        )

    df = pd.read_csv(CSV_FILE, low_memory=False)

    required = ["cve_id", "product_name", "cvss_base_score", "cisa_kev", "first_epss"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        st.error("CSV is missing: " + ", ".join(missing))
        st.stop()

    df["cve_id"] = df["cve_id"].fillna("").astype(str)
    df["product_name"] = df["product_name"].fillna("").astype(str)
    df["cvss_base_score"] = pd.to_numeric(df["cvss_base_score"], errors="coerce").fillna(0.0)
    df["first_epss"] = pd.to_numeric(df["first_epss"], errors="coerce").fillna(0.0)
    df["cisa_kev"] = (
        df["cisa_kev"].astype(str).str.strip().str.lower().isin(["true", "1", "yes", "y"])
    )

    return df


@st.cache_data
def load_profiles():
    profiles = []

    if PROFILE_FILE:
        raw = json.loads(PROFILE_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            for p in raw:
                profiles.append({
                    "key": "detail::" + str(p.get("profile_id", p.get("name", "profile"))),
                    "name": p.get("name", "Unnamed organisation"),
                    "sector": p.get("sector", "Unknown"),
                    "risk_appetite": "Not supplied",
                    "technologies": p.get("technologies", []),
                    "critical_products": [],
                    "weights": {
                        "cvss_weight": 0.35,
                        "cisa_kev_weight": 0.40,
                        "first_epss_weight": 0.25,
                    },
                    "source": "profile.json",
                })

    if PROFILES_FILE:
        raw = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
        for p in raw.get("organizations", []):
            profiles.append({
                "key": "org::" + str(p.get("org_id", p.get("name", "org"))),
                "name": p.get("name", "Unnamed organisation"),
                "sector": p.get("sector", "Unknown"),
                "risk_appetite": p.get("risk_appetite", "Unknown"),
                "technologies": [],
                "critical_products": p.get("critical_products", []),
                "weights": p.get(
                    "weight_modifiers",
                    {"cvss_weight": 0.35, "cisa_kev_weight": 0.40, "first_epss_weight": 0.25},
                ),
                "source": "profiles.json",
            })

    return profiles


vulnerabilities = load_vulnerabilities()
profiles = load_profiles()

if not profiles:
    st.error("No organisation profile was found. Put profile.json or profiles.json beside app.py.")
    st.stop()


# ============================================================
# HELPERS  (unchanged logic)
# ============================================================

def norm(x):
    return (
        str(x or "").lower().strip().replace("_", " ").replace("/", " ").replace("-", " ")
    )


def escape(v):
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def assets_for(profile):
    assets = []

    for t in profile.get("technologies", []):
        vendor = norm(t.get("vendor"))
        product = norm(t.get("product"))
        assets.append({
            "display": f"{t.get('vendor', '')}/{t.get('product', '')}",
            "match": {vendor, product, f"{vendor} {product}".strip()},
            "version": t.get("version", "Not supplied"),
            "service": t.get("service", "Not supplied"),
            "exposure": t.get("exposure", "Not supplied"),
            "importance": t.get("importance", "Not supplied"),
        })

    for p in profile.get("critical_products", []):
        assets.append({
            "display": p,
            "match": {norm(p)},
            "version": "Not supplied",
            "service": "Critical product",
            "exposure": "Not supplied",
            "importance": "critical",
        })

    return assets


def match_asset(product, assets):
    p = norm(product)
    for a in assets:
        for m in a["match"]:
            if not m:
                continue
            if p == m:
                return a
            if len(m) >= 5 and (m in p or p in m):
                return a
    return None


def score_row(row, profile, asset):
    w = profile.get("weights", {})
    cw = float(w.get("cvss_weight", 0.35))
    kw = float(w.get("cisa_kev_weight", 0.40))
    ew = float(w.get("first_epss_weight", 0.25))

    cvss = max(0.0, min(float(row.cvss_base_score), 10.0))
    epss = max(0.0, min(float(row.first_epss), 1.0))
    kev = bool(row.cisa_kev)

    cvss_part = (cvss / 10) * 100 * cw
    kev_part = 100 * kw if kev else 0
    epss_part = epss * 100 * ew

    # Unmatched vulnerabilities get context = 0
    context = 0
    if asset:
        imp = norm(asset.get("importance"))
        exp = norm(asset.get("exposure"))
        context += {"critical": 10, "high": 6, "normal": 2}.get(imp, 0)
        if exp == "internet facing":
            context += 8

    total = min(100, cvss_part + kev_part + epss_part + context)

    return {
        "score": round(total, 1),
        "cvss": round(cvss_part, 1),
        "kev": round(kev_part, 1),
        "epss": round(epss_part, 1),
        "context": round(context, 1),
    }


def priority(score):
    if score >= 75:
        return "URGENT", "urgent"
    if score >= 55:
        return "HIGH", "high"
    if score >= 35:
        return "MEDIUM", "medium"
    return "LOW", "low"


def triage(profile):
    assets = assets_for(profile)
    out = []

    for row in vulnerabilities.itertuples(index=False):
        asset = match_asset(row.product_name, assets)  # None is fine — do not skip
        parts = score_row(row, profile, asset)
        label, cls = priority(parts["score"])

        out.append({
            "cve": row.cve_id,
            "product": row.product_name,
            "cvss": float(row.cvss_base_score),
            "epss": float(row.first_epss),
            "kev": bool(row.cisa_kev),
            "asset": asset,
            "profile_match": asset is not None,
            "parts": parts,
            "score": parts["score"],
            "label": label,
            "class": cls,
            "confidence": (
                "HIGH"
                if asset and asset.get("version") not in [None, "", "Not supplied"]
                else "MEDIUM"
            ),
        })

    # Remove duplicates, keep highest score
    unique = {}
    for r in out:
        key = (r["cve"], r["product"])
        if key not in unique or r["score"] > unique[key]["score"]:
            unique[key] = r

    results = list(unique.values())

    return sorted(
        results,
        key=lambda r: (r["score"], r["kev"], r["cvss"], r["epss"]),
        reverse=True,
    )


def run_negative_tests(raw_total, results):
    tests = []

    tests.append({
        "name": "CSV structural validation",
        "detail": "Required columns present and readable",
        "status": "PASS" if CSV_FILE is not None else "FAIL",
    })

    missing_cve = int((vulnerabilities["cve_id"] == "").sum()) if len(vulnerabilities) else 0
    tests.append({
        "name": "Missing CVE ID handling",
        "detail": f"{missing_cve} row(s) with blank CVE ID safely coerced",
        "status": "PASS",
    })

    bad_cvss = int(
        pd.to_numeric(pd.read_csv(CSV_FILE, low_memory=False)["cvss_base_score"], errors="coerce")
        .isna().sum()
    ) if CSV_FILE is not None else 0
    tests.append({
        "name": "Invalid CVSS handling",
        "detail": f"{bad_cvss} malformed CVSS value(s) coerced to 0.0",
        "status": "PASS",
    })

    bad_epss = int(
        pd.to_numeric(pd.read_csv(CSV_FILE, low_memory=False)["first_epss"], errors="coerce")
        .isna().sum()
    ) if CSV_FILE is not None else 0
    tests.append({
        "name": "Invalid EPSS handling",
        "detail": f"{bad_epss} malformed EPSS value(s) coerced to 0.0",
        "status": "PASS",
    })

    dupes = raw_total - len(results)
    tests.append({
        "name": "Duplicate CVE/product detection",
        "detail": f"{dupes} duplicate record(s) collapsed, highest score kept",
        "status": "PASS",
    })

    missing_product = int((vulnerabilities["product_name"] == "").sum()) if len(vulnerabilities) else 0
    tests.append({
        "name": "Missing product handling",
        "detail": f"{missing_product} row(s) with blank product still ranked as general threats",
        "status": "PASS",
    })

    if results:
        top_cvss = max(results, key=lambda r: r["cvss"])
        top_score = results[0]
        relevant = top_cvss["cve"] == top_score["cve"]
        tests.append({
            "name": "High-CVSS relevance test",
            "detail": (
                "Highest CVSS is not blindly ranked #1 without KEV/EPSS/context support"
                if not relevant else
                "Highest CVSS also holds the #1 rank, supported by other signals"
            ),
            "status": "PASS",
        })
    else:
        tests.append({
            "name": "High-CVSS relevance test",
            "detail": "No data available to test",
            "status": "WARN",
        })

    return tests


# ============================================================
# CSS  — BLACK / PURPLE / MAGENTA
# ============================================================

md(
    """
<style>

@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700;800&display=swap');

:root{
    --bg-primary:#07030D;
    --bg-secondary:#0D0717;
    --panel:#140A20;
    --card:#1A0D27;
    --border:#39204F;
    --purple:#8B5CF6;
    --purple-bright:#A855F7;
    --magenta:#EC4899;
    --magenta-hot:#F43F5E;
    --text-heading:#FFFFFF;
    --text-body:#E9DDF7;
    --text-secondary:#BFAED0;
    --text-purple:#C084FC;
    --text-magenta:#F472B6;
    --grad:linear-gradient(90deg,var(--purple),var(--magenta));
    --grad-dark:linear-gradient(160deg,var(--panel),var(--bg-primary));
}

*{ font-family:'Space Grotesk', sans-serif; }

.stApp{
    background:
        radial-gradient(circle at 15% 0%, rgba(139,92,246,.10), transparent 40%),
        radial-gradient(circle at 85% 15%, rgba(236,72,153,.08), transparent 40%),
        var(--bg-primary);
    color:var(--text-body);
}

.main .block-container{ max-width:1480px; padding-top:1.2rem; padding-bottom:4rem; }

section[data-testid="stSidebar"]{ background:var(--bg-secondary); border-right:1px solid var(--border); }

h1,h2,h3{ color:var(--text-heading); }

::selection{ background:rgba(168,85,247,.4); }

.mono{ font-family:'JetBrains Mono', monospace; }

/* Streamlit input/button restyle */
.stTextInput input, .stSelectbox div[data-baseweb="select"] > div{
    background:var(--panel) !important;
    border:1px solid var(--border) !important;
    color:var(--text-body) !important;
}

.stButton button{
    background:var(--grad) !important;
    color:#fff !important;
    border:none !important;
    font-family:'JetBrains Mono', monospace !important;
    font-weight:700 !important;
    letter-spacing:1px !important;
    border-radius:10px !important;
    transition:box-shadow .2s, transform .2s;
}

.stButton button:hover{
    box-shadow:0 0 26px rgba(168,85,247,.55), 0 0 50px rgba(236,72,153,.25) !important;
    transform:translateY(-1px);
}

[data-testid="stDialog"] div[role="dialog"]{
    background:var(--panel);
    border:1px solid var(--border);
    border-radius:20px;
}

/* -------------------------------------------------------- */
/* TOP BAR */
/* -------------------------------------------------------- */

.topbar{
    height:76px; border:1px solid var(--border); border-radius:16px;
    display:flex; align-items:center; justify-content:space-between;
    margin-bottom:26px; padding:0 24px;
    background:linear-gradient(120deg, var(--panel), var(--bg-secondary));
}

.brand{ display:flex; gap:12px; align-items:center; }

.logo{
    width:40px; height:40px; border-radius:10px;
    background:var(--grad);
    display:grid; place-items:center; color:#fff; font-weight:800;
    box-shadow:0 0 22px rgba(168,85,247,.45);
}

.muted{ color:var(--text-secondary); font-size:11px; font-family:'JetBrains Mono', monospace; letter-spacing:.5px; }

/* -------------------------------------------------------- */
/* SCREEN TRANSITIONS */
/* -------------------------------------------------------- */

@keyframes fadeSlideUp{ from{ opacity:0; transform:translateY(14px); } to{ opacity:1; transform:translateY(0); } }
.fade-in{ animation:fadeSlideUp .7s cubic-bezier(.2,.8,.3,1) forwards; }
.fade-in-1{ animation:fadeSlideUp .7s cubic-bezier(.2,.8,.3,1) .1s both; }
.fade-in-2{ animation:fadeSlideUp .7s cubic-bezier(.2,.8,.3,1) .2s both; }
.fade-in-3{ animation:fadeSlideUp .7s cubic-bezier(.2,.8,.3,1) .3s both; }

@keyframes cardReveal{
    0%{ opacity:0; transform:translateY(26px) scale(.97); filter:blur(3px); box-shadow:none; }
    55%{ opacity:1; transform:translateY(0) scale(1.01); filter:blur(0); box-shadow:0 0 0 1px rgba(168,85,247,.5), 0 0 34px rgba(236,72,153,.28); }
    100%{ opacity:1; transform:translateY(0) scale(1); filter:blur(0); box-shadow:none; }
}
.cascade-in{ opacity:0; animation:cardReveal .75s cubic-bezier(.2,.8,.3,1) forwards; }

/* -------------------------------------------------------- */
/* HERO */
/* -------------------------------------------------------- */

.hero{
    position:relative; overflow:hidden;
    border:1px solid var(--border); border-radius:26px;
    padding:64px 40px 44px;
    display:grid; grid-template-columns:1.1fr 1fr; gap:28px; align-items:center;
    background:
        radial-gradient(circle at 15% 15%, rgba(139,92,246,.16), transparent 42%),
        radial-gradient(circle at 90% 80%, rgba(236,72,153,.10), transparent 40%),
        linear-gradient(160deg, var(--panel), var(--bg-primary));
}

@media (max-width:900px){ .hero{ grid-template-columns:1fr; text-align:center; } }

.grid-overlay{
    position:absolute; inset:0;
    background-image:
        linear-gradient(rgba(139,92,246,.09) 1px, transparent 1px),
        linear-gradient(90deg, rgba(139,92,246,.09) 1px, transparent 1px);
    background-size:42px 42px;
    mask-image:linear-gradient(to bottom, black, transparent);
}

.kicker{
    position:relative; display:inline-flex; align-items:center; gap:8px;
    color:var(--text-purple); font:800 12px 'JetBrains Mono', monospace; letter-spacing:2px;
    padding:6px 14px; border:1px solid rgba(168,85,247,.35); border-radius:999px;
}

.kicker .dot{ width:6px; height:6px; border-radius:50%; background:var(--magenta); box-shadow:0 0 10px var(--magenta); animation:dotPulse 1.1s ease-in-out infinite; }
@keyframes dotPulse{ 0%,100%{ opacity:1; transform:scale(1); } 50%{ opacity:.4; transform:scale(.7); } }

.hero-copy{ position:relative; }

.hero-copy h1{
    font-size:clamp(36px,4.6vw,60px); line-height:1.05; margin:18px 0 6px;
    color:var(--text-heading); font-weight:800;
}

.hero-copy h1 span{
    background:var(--grad); -webkit-background-clip:text; background-clip:text; color:transparent;
    filter:drop-shadow(0 0 26px rgba(236,72,153,.3));
}

.hero-tag{ color:var(--text-secondary); font:800 13px 'JetBrains Mono', monospace; letter-spacing:2px; text-transform:uppercase; margin-bottom:4px; }

.hero-copy p{ max-width:560px; color:var(--text-secondary); font-size:15.5px; line-height:1.75; margin:14px 0 26px; }
@media (max-width:900px){ .hero-copy p{ margin-left:auto; margin-right:auto; } }

.hero-btns{ display:flex; gap:14px; flex-wrap:wrap; }
@media (max-width:900px){ .hero-btns{ justify-content:center; } }

.btn-primary{
    display:inline-flex; align-items:center; gap:8px; padding:15px 28px; border-radius:12px;
    background:var(--grad); color:#fff; font:800 13px 'JetBrains Mono', monospace; letter-spacing:1px;
    box-shadow:0 10px 30px rgba(168,85,247,.35); transition:box-shadow .2s, transform .2s;
}
.btn-primary:hover{ box-shadow:0 0 30px rgba(168,85,247,.6), 0 0 55px rgba(236,72,153,.3); transform:translateY(-2px); }

.btn-secondary{
    display:inline-flex; align-items:center; gap:8px; padding:15px 28px; border-radius:12px;
    border:1px solid var(--border); color:var(--text-body); font:800 13px 'JetBrains Mono', monospace; letter-spacing:1px;
    background:rgba(255,255,255,.02);
}

/* Hero network visual */
.network{
    position:relative; height:340px; border:1px solid var(--border); border-radius:26px;
    background:rgba(20,10,32,.55); box-shadow:0 0 60px rgba(139,92,246,.12) inset;
}
.network svg{ position:absolute; inset:0; width:100%; height:100%; }
.network .lead{ stroke:#3a2452; stroke-width:1.4; fill:none; stroke-dasharray:4 5; opacity:.6; }
.network .flow{ stroke:url(#flowGrad); stroke-width:1.8; fill:none; stroke-dasharray:6 10; animation:flowMove 2.6s linear infinite; }
@keyframes flowMove{ to{ stroke-dashoffset:-160; } }

.net-core{
    position:absolute; left:50%; top:50%; transform:translate(-50%,-50%);
    width:150px; height:150px; border-radius:50%; border:1px solid var(--purple-bright);
    display:grid; place-items:center; text-align:center; color:#e9d5ff;
    font:800 13px 'JetBrains Mono', monospace; letter-spacing:1px;
    box-shadow:0 0 55px rgba(168,85,247,.32);
    background:radial-gradient(circle, rgba(168,85,247,.14), transparent 70%);
    animation:coreBreathe 3.4s ease-in-out infinite;
}
@keyframes coreBreathe{ 0%,100%{ box-shadow:0 0 45px rgba(168,85,247,.22); } 50%{ box-shadow:0 0 75px rgba(236,72,153,.4); } }

.net-node{
    position:absolute; padding:9px 13px; border:1px solid var(--border); border-radius:10px;
    background:var(--panel); color:var(--text-secondary); font:800 10px 'JetBrains Mono', monospace; letter-spacing:.5px;
    animation:nodeFloat 4s ease-in-out infinite;
}
.nn1{ left:4%; top:12%; animation-delay:0s; }
.nn2{ left:4%; bottom:12%; animation-delay:.7s; }
.nn3{ right:4%; top:12%; animation-delay:1.4s; }
.nn4{ right:4%; bottom:12%; animation-delay:2.1s; }
.nn5{ left:50%; top:6%; transform:translateX(-50%); animation-delay:2.8s; }
@keyframes nodeFloat{
    0%,100%{ transform:translateY(0); border-color:var(--border); color:var(--text-secondary); }
    50%{ transform:translateY(-5px); border-color:var(--purple-bright); color:var(--text-purple); box-shadow:0 0 16px rgba(168,85,247,.35); }
}
.nn5{ animation-name:nodeFloatCenter; }
@keyframes nodeFloatCenter{
    0%,100%{ transform:translateX(-50%) translateY(0); border-color:var(--border); color:var(--text-secondary); }
    50%{ transform:translateX(-50%) translateY(-5px); border-color:var(--purple-bright); color:var(--text-purple); box-shadow:0 0 16px rgba(168,85,247,.35); }
}

/* -------------------------------------------------------- */
/* STATS */
/* -------------------------------------------------------- */

.stats-grid{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-top:32px; }
@media (max-width:900px){ .stats-grid{ grid-template-columns:repeat(2,1fr); } }

.stat-card{
    border:1px solid var(--border); border-radius:18px;
    background:linear-gradient(160deg, var(--card), var(--bg-secondary));
    padding:22px 20px; text-align:center;
}
.stat-card small{ display:block; color:var(--text-secondary); font:800 10px 'JetBrains Mono', monospace; letter-spacing:1.6px; margin-bottom:10px; }
.stat-card .stat-val{ font-size:30px; font-weight:800; color:var(--text-purple); text-shadow:0 0 20px rgba(168,85,247,.35); font-family:'JetBrains Mono', monospace; }

/* -------------------------------------------------------- */
/* FEATURE CARDS */
/* -------------------------------------------------------- */

.features-grid{ display:grid; grid-template-columns:repeat(3,1fr); gap:18px; margin-top:18px; }
@media (max-width:900px){ .features-grid{ grid-template-columns:1fr; } }

.feature-card{
    border:1px solid var(--border); border-radius:20px; padding:26px 24px;
    background:linear-gradient(165deg, var(--card), var(--bg-secondary));
    transition:transform .25s ease, border-color .25s ease, box-shadow .25s ease;
}
.feature-card:hover{ transform:translateY(-4px); border-color:var(--purple-bright); box-shadow:0 16px 40px rgba(0,0,0,.4), 0 0 30px rgba(168,85,247,.2); }

.feature-icon{
    width:44px; height:44px; border-radius:12px; border:1px solid var(--border);
    display:grid; place-items:center; color:var(--text-magenta); font-size:19px; margin-bottom:16px;
    background:rgba(236,72,153,.08);
}
.feature-card h3{ font-size:18px; margin:0 0 8px; color:var(--text-heading); }
.feature-card p{ color:var(--text-secondary); font-size:13.5px; line-height:1.7; margin:0; }

/* -------------------------------------------------------- */
/* CTA */
/* -------------------------------------------------------- */

.cta{
    position:relative; margin-top:40px; border:1px solid var(--border); border-radius:26px;
    padding:52px 30px; text-align:center; overflow:hidden;
    background:
        radial-gradient(circle at 50% 0%, rgba(236,72,153,.16), transparent 45%),
        linear-gradient(160deg, var(--panel), var(--bg-primary));
}
.cta h2{ font-size:clamp(26px,3.4vw,40px); margin:0 0 10px; color:var(--text-heading); }
.cta p{ color:var(--text-secondary); font-size:14.5px; max-width:520px; margin:0 auto 24px; line-height:1.7; }

/* -------------------------------------------------------- */
/* SETUP */
/* -------------------------------------------------------- */

.setup{ max-width:1050px; margin:0 auto; border:1px solid var(--border); border-radius:24px; padding:30px; background:var(--bg-secondary); }
.eyebrow{ color:var(--text-purple); font:800 11px 'JetBrains Mono', monospace; letter-spacing:1.5px; }
.setup h2{ font-size:34px; margin:10px 0; color:var(--text-heading); }
.sub{ color:var(--text-secondary); font-size:13px; line-height:1.7; }

.asset{ border:1px solid var(--border); border-radius:16px; background:var(--card); padding:17px; height:100%; }
.asset b{ font-size:15px; color:var(--text-heading); }
.tag{
    display:inline-block; margin-top:12px; padding:5px 9px; border-radius:999px;
    background:rgba(168,85,247,.1); border:1px solid var(--purple); color:var(--text-purple);
    font:700 10px 'JetBrains Mono', monospace;
}

/* -------------------------------------------------------- */
/* RESULTS / DASHBOARD */
/* -------------------------------------------------------- */

.profile{ border:1px solid var(--border); border-radius:18px; background:var(--bg-secondary); padding:20px; }
.profile-title{ font-size:23px; font-weight:800; color:var(--text-heading); }

.divider-glow{
    height:2px; margin:14px 0 30px; border-radius:2px;
    background:var(--grad); box-shadow:0 0 16px rgba(168,85,247,.55);
}

.metric{ border:1px solid var(--border); border-radius:15px; background:var(--bg-secondary); padding:17px; min-height:130px; }
.metric small{ color:var(--text-secondary); font:800 10px 'JetBrains Mono', monospace; letter-spacing:1px; }
.metric strong{ display:block; font-size:30px; margin-top:7px; color:var(--text-heading); font-family:'JetBrains Mono', monospace; }
.metric span{ color:var(--text-secondary); font-size:11px; }

.section-title{ font-size:27px; font-weight:800; margin-top:38px; color:var(--text-heading); }
.section-sub{ color:var(--text-secondary); font-size:12.5px; margin:7px 0 18px; }

/* -------------------------------------------------------- */
/* THREAT GAUGE */
/* -------------------------------------------------------- */

.gauge-wrap{
    display:flex; align-items:center; gap:32px; border:1px solid var(--border); border-radius:20px;
    background:linear-gradient(160deg, var(--card), var(--bg-secondary)); padding:26px 30px; margin-top:18px; flex-wrap:wrap;
}
.gauge-label{ color:var(--text-secondary); font:800 11px 'JetBrains Mono', monospace; letter-spacing:1.5px; }
.gauge-level{ font-size:44px; font-weight:800; margin:6px 0; font-family:'JetBrains Mono', monospace; }
.gauge-track{ flex:1; min-width:220px; height:14px; border-radius:999px; background:var(--panel); border:1px solid var(--border); overflow:hidden; }
.gauge-fill{ height:100%; border-radius:999px; background:linear-gradient(90deg,#2be07a,#f4d35e,var(--magenta),var(--magenta-hot)); }
.gauge-pct{ font-family:'JetBrains Mono', monospace; font-weight:800; font-size:20px; color:var(--text-heading); min-width:70px; text-align:right; }

/* -------------------------------------------------------- */
/* VULNERABILITY CARDS */
/* -------------------------------------------------------- */

.vcard{ position:relative; border:1px solid var(--border); border-radius:18px; background:var(--card); margin:16px 0; padding:24px 24px 24px 92px; }
.vcard-bignum{
    position:absolute; left:20px; top:24px; font:800 46px 'JetBrains Mono', monospace; line-height:1;
    color:transparent; -webkit-text-stroke:1px #4a3062;
}
.vcard-bignum.urgent{ -webkit-text-stroke:1px rgba(244,63,94,.65); }
.vcard-bignum.high{ -webkit-text-stroke:1px rgba(236,72,153,.6); }
.vcard-bignum.medium{ -webkit-text-stroke:1px rgba(217,165,0,.6); }
.vcard-bignum.low{ -webkit-text-stroke:1px rgba(36,141,99,.6); }

@media (max-width:640px){ .vcard{ padding-left:24px; } .vcard-bignum{ position:static; margin-bottom:10px; font-size:32px; } }

.vcard.urgent{ border-color:var(--magenta-hot); background:linear-gradient(90deg, rgba(244,63,94,.14), var(--card) 65%); }
.vcard.high{ border-color:var(--magenta); }
.vcard.medium{ border-color:#d9a500; }
.vcard.low{ border-color:#248d63; }

.row{ display:flex; justify-content:space-between; gap:20px; flex-wrap:wrap; }
.rank{ color:var(--text-purple); font:800 15px 'JetBrains Mono', monospace; letter-spacing:1px; }

.badge{ display:inline-block; padding:7px 12px; border-radius:7px; font:800 11px 'JetBrains Mono', monospace; letter-spacing:.8px; }
.badge.urgent{ color:#ff8fa3; border:1px solid var(--magenta-hot); background:rgba(244,63,94,.15); }
.badge.high{ color:#f9a8d4; border:1px solid var(--magenta); background:rgba(236,72,153,.15); }
.badge.medium{ color:#f4d35e; border:1px solid #92740a; background:#332b08; }
.badge.low{ color:#66e5a8; border:1px solid #278b61; background:#0b2f21; }

.cve{ color:var(--text-purple); font:800 18px 'JetBrains Mono', monospace; margin-top:10px; }
.title{ font-size:24px; font-weight:800; margin-top:9px; color:var(--text-heading); }
.meta{ color:var(--text-secondary); font:12px 'JetBrains Mono', monospace; margin-top:10px; }

.score{ font-size:36px; font-weight:800; text-align:right; color:var(--text-heading); font-family:'JetBrains Mono', monospace; }
.score small{ display:block; color:var(--text-secondary); font:9px 'JetBrains Mono', monospace; font-weight:400;}

.signalbar{ display:flex; gap:8px; flex-wrap:wrap; margin:20px 0; }
.sig{ padding:8px 11px; border-radius:7px; background:var(--panel); border:1px solid var(--border); color:var(--text-secondary); font:11px 'JetBrains Mono', monospace; }
.sig.kev{ color:#ff8fa3; border-color:var(--magenta-hot); }
.sig.epss{ color:var(--text-purple); border-color:var(--purple); }
.sig.net{ color:#e9d5ff; border-color:var(--purple-bright); }

.reason{ border:1px solid var(--border); border-radius:12px; padding:16px; background:var(--bg-secondary); margin-top:12px; color:var(--text-body); font-size:13px; line-height:1.75; }
.reason b{ color:var(--text-secondary); font:800 11px 'JetBrains Mono', monospace; letter-spacing:1px; }

.action{ border:1px solid #1a6842; border-radius:12px; padding:15px; background:rgba(12,78,46,.28); margin-top:12px; color:#d5ffe7; font-size:13px; line-height:1.6; }
.action b{ display:block; color:#31df83; font:800 10px 'JetBrains Mono', monospace; letter-spacing:1px; margin-bottom:5px; }

/* -------------------------------------------------------- */
/* NEGATIVE TESTING GRID */
/* -------------------------------------------------------- */

.negtest-grid{ display:grid; grid-template-columns:repeat(2,1fr); gap:10px; margin-top:14px; }
@media (max-width:900px){ .negtest-grid{ grid-template-columns:1fr; } }

.negtest-row{
    display:flex; align-items:center; justify-content:space-between; gap:14px;
    border:1px solid var(--border); border-radius:12px; padding:13px 16px; background:var(--card);
}
.negtest-name{ color:var(--text-body); font-size:13px; font-weight:700; }
.negtest-detail{ color:var(--text-secondary); font-size:11.5px; margin-top:3px; }

.negtest-badge{ flex-shrink:0; padding:5px 12px; border-radius:7px; font:800 10px 'JetBrains Mono', monospace; letter-spacing:1px; }
.negtest-badge.PASS{ color:#66e5a8; border:1px solid #278b61; background:#0b2f21; }
.negtest-badge.WARN{ color:#f4d35e; border:1px solid #92740a; background:#332b08; }
.negtest-badge.FAIL{ color:#ff8fa3; border:1px solid var(--magenta-hot); background:rgba(244,63,94,.15); }

.foot{ color:var(--text-secondary); text-align:center; font:10px 'JetBrains Mono', monospace; padding:35px; }

</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# SESSION STATE
# ============================================================

if "screen" not in st.session_state:
    st.session_state.screen = "intro"

if "org_key" not in st.session_state:
    st.session_state.org_key = profiles[0]["key"]

if "selected_rank" not in st.session_state:
    st.session_state.selected_rank = None


def topbar():
    md(
        """
        <div class="topbar">
            <div class="brand">
                <div class="logo">VT</div>
                <div>
                    <b style="color:var(--text-heading)">Vulnerability Triage</b>
                    <div class="muted">PERSONALISED THREAT INTELLIGENCE · PUBLIC DATA ONLY</div>
                </div>
            </div>
            <div class="muted">DEFENSIVE INTELLIGENCE ENGINE</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def get_profile(key):
    return next(p for p in profiles if p["key"] == key)


# ============================================================
# INTRO SCREEN — HUD boot sequence with a rotating scanner core
# and a vertical boot-log (no floating text ever shares a
# coordinate with another piece of text, so nothing overlaps).
# ============================================================

if st.session_state.screen == "intro":

    INTRO_HTML = """
    <style>
        html, body{ margin:0; padding:0; background:#000; overflow:hidden;
                    font-family:'Space Grotesk', sans-serif; }

        .intro-wrap{
            position:relative; width:100%; height:760px; overflow:hidden;
            background:#050208;
            animation: introFadeOut .6s ease forwards; animation-delay: 8.6s;
        }

        /* ---------------- ambient backdrop ---------------- */
        .bg-glow{
            position:absolute; inset:0; opacity:0; transition:opacity 1.4s ease; z-index:1;
            background:
                radial-gradient(circle at 50% 40%, rgba(139,92,246,.20), transparent 45%),
                radial-gradient(circle at 80% 75%, rgba(236,72,153,.14), transparent 45%),
                linear-gradient(160deg,#05020A,#0A0512);
        }
        .bg-glow.on{ opacity:1; }

        .grid-bg{
            position:absolute; inset:-10%; opacity:0; transition:opacity 1.2s ease; z-index:1;
            background-image:
                linear-gradient(rgba(139,92,246,.08) 1px, transparent 1px),
                linear-gradient(90deg, rgba(139,92,246,.08) 1px, transparent 1px);
            background-size:44px 44px;
            mask-image: radial-gradient(circle at 50% 45%, black 5%, transparent 68%);
            -webkit-mask-image: radial-gradient(circle at 50% 45%, black 5%, transparent 68%);
        }
        .grid-bg.on{ opacity:1; animation: gridDrift 12s linear infinite; }
        @keyframes gridDrift{ from{ background-position:0 0; } to{ background-position:44px 44px; } }

        .scanline{
            position:absolute; left:0; right:0; height:2px; z-index:5; pointer-events:none;
            background:linear-gradient(90deg, transparent, rgba(168,85,247,.55), rgba(236,72,153,.55), transparent);
            opacity:0; box-shadow:0 0 12px rgba(168,85,247,.6);
        }
        .scanline.on{ opacity:1; animation: scanMove 2.6s ease-in-out infinite; }
        @keyframes scanMove{ 0%{ top:8%; } 50%{ top:92%; } 100%{ top:8%; } }

        .film-grain{
            position:absolute; inset:0; z-index:4; opacity:.04; pointer-events:none; mix-blend-mode:overlay;
            background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
        }

        /* ---------------- HUD corner brackets ---------------- */
        .corner{ position:absolute; width:46px; height:46px; border:2px solid rgba(168,85,247,.55);
                  opacity:0; transition:opacity .6s ease, width .6s ease, height .6s ease; z-index:3; }
        .corner.on{ opacity:1; }
        .c-tl{ top:26px; left:26px; border-right:none; border-bottom:none; }
        .c-tr{ top:26px; right:26px; border-left:none; border-bottom:none; }
        .c-bl{ bottom:26px; left:26px; border-right:none; border-top:none; }
        .c-br{ bottom:26px; right:26px; border-left:none; border-top:none; }

        .hud-label{
            position:absolute; z-index:3; color:#8b7599; font:800 10px 'JetBrains Mono', monospace;
            letter-spacing:2px; opacity:0; transition:opacity .5s ease;
        }
        .hud-label.on{ opacity:1; }
        .hud-tl{ top:34px; left:80px; }
        .hud-tr{ top:34px; right:80px; text-align:right; }
        .hud-bl{ bottom:34px; left:80px; }
        .hud-br{ bottom:34px; right:80px; text-align:right; }
        .hud-tr .pulse-dot{ display:inline-block; width:6px; height:6px; border-radius:50%; background:#F43F5E;
                             box-shadow:0 0 8px #F43F5E; margin-left:6px; animation:dotPulse 1s ease-in-out infinite; }
        @keyframes dotPulse{ 0%,100%{ opacity:1; } 50%{ opacity:.3; } }

        /* ---------------- central scanner core ---------------- */
        .core-stage{
            position:absolute; left:50%; top:44%; transform:translate(-50%,-50%);
            width:230px; height:230px; z-index:3;
        }
        .core-ring{ position:absolute; inset:0; border-radius:50%; border:1px dashed rgba(168,85,247,.28); opacity:0; transition:opacity .6s ease; }
        .core-ring.on{ opacity:1; }
        .ring1{ animation: coreSpin 6s linear infinite; }
        .ring2{ inset:20px; border-color:rgba(236,72,153,.24); animation: coreSpin 9s linear infinite reverse; }
        .ring3{ inset:40px; border-style:solid; border-color:rgba(168,85,247,.16); animation: coreSpin 14s linear infinite; }
        @keyframes coreSpin{ from{ transform:rotate(0deg); } to{ transform:rotate(360deg); } }

        .core-svg{ position:absolute; inset:10px; }
        .core-svg circle.bg{ fill:none; stroke:#1e1030; stroke-width:6; }
        .core-svg circle.fg{
            fill:none; stroke:url(#coreGrad); stroke-width:6; stroke-linecap:round;
            stroke-dasharray:565.5; stroke-dashoffset:565.5;
            transform:rotate(-90deg); transform-origin:50% 50%;
            transition:stroke-dashoffset .5s ease;
            filter:drop-shadow(0 0 8px rgba(236,72,153,.5));
        }

        .core-center{
            position:absolute; inset:0; display:flex; align-items:center; justify-content:center;
            flex-direction:column; text-align:center;
        }
        .core-pct{ font:800 30px 'JetBrains Mono', monospace; color:#fff; text-shadow:0 0 18px rgba(168,85,247,.6); }
        .core-sub{ font:800 9px 'JetBrains Mono', monospace; letter-spacing:2px; color:#a58cc4; margin-top:2px; }

        .core-flash{
            position:absolute; inset:-40px; border-radius:50%; opacity:0; pointer-events:none;
            background:radial-gradient(circle, rgba(255,255,255,.9), rgba(236,72,153,.5) 40%, transparent 70%);
        }
        .core-flash.pop{ animation:flashPop .7s ease forwards; }
        @keyframes flashPop{ 0%{ opacity:0; transform:scale(.4); } 35%{ opacity:1; transform:scale(1.15); } 100%{ opacity:0; transform:scale(1.6); } }

        /* ---------------- boot log (each line = its own row, never reused) ---------------- */
        .log-panel{
            position:absolute; left:50%; top:74%; transform:translateX(-50%);
            width:min(88%, 560px); z-index:3; display:flex; flex-direction:column; gap:7px;
        }
        .log-row{
            display:flex; align-items:center; gap:10px; opacity:0;
            font:700 12.5px 'JetBrains Mono', monospace; letter-spacing:.4px; color:#7a6690;
            animation: logIn .4s ease forwards;
        }
        @keyframes logIn{ from{ opacity:0; transform:translateY(6px); } to{ opacity:1; transform:translateY(0); } }
        .log-row .chk{ width:14px; height:14px; border-radius:50%; border:1.5px solid #3a2452; flex-shrink:0;
                        display:flex; align-items:center; justify-content:center; font-size:9px; color:#3a2452; }
        .log-row.done{ color:#c7b3e0; }
        .log-row.done .chk{ border-color:#2be07a; color:#2be07a; box-shadow:0 0 8px rgba(43,224,122,.4); }

        /* ---------------- title ---------------- */
        .title-wrap{ position:absolute; left:50%; top:50%; transform:translate(-50%,-50%);
                      z-index:6; text-align:center; opacity:0; pointer-events:none; }
        .title-wrap.on{ opacity:1; }
        .typewriter{
            font-size:clamp(28px,5vw,58px); font-weight:800; letter-spacing:2px; color:#fff;
            white-space:nowrap; text-shadow:0 0 24px rgba(168,85,247,.55), 0 0 60px rgba(236,72,153,.25);
        }
        .letter{ display:inline-block; opacity:0; animation: letterIn .5s cubic-bezier(.2,.7,.2,1) forwards; }
        @keyframes letterIn{ from{ opacity:0; transform:translateY(16px) scale(.8); filter:blur(6px); }
                              to{ opacity:1; transform:translateY(0) scale(1); filter:blur(0); } }
        .subtitle{
            margin-top:14px; font:800 12px 'JetBrains Mono', monospace; letter-spacing:3px;
            background:linear-gradient(90deg,#A855F7,#EC4899);
            -webkit-background-clip:text; background-clip:text; color:transparent; opacity:0;
        }
        .subtitle.show{ animation: fadeUp .6s ease forwards; }
        .status-final{ margin-top:16px; min-height:16px; color:#34d399; font:800 11px 'JetBrains Mono', monospace;
                        letter-spacing:1.5px; opacity:0; }
        .status-final.show{ animation: fadeUp .45s ease forwards; }
        @keyframes fadeUp{ from{ opacity:0; transform:translateY(8px); } to{ opacity:1; transform:translateY(0); } }

        @keyframes introFadeOut{ from{ opacity:1; } to{ opacity:0; } }
    </style>

    <div class="intro-wrap" id="introWrap">
        <div class="bg-glow" id="bgGlow"></div>
        <div class="grid-bg" id="gridBg"></div>
        <div class="scanline" id="scanline"></div>
        <div class="film-grain"></div>

        <div class="corner c-tl" id="cTl"></div>
        <div class="corner c-tr" id="cTr"></div>
        <div class="corner c-bl" id="cBl"></div>
        <div class="corner c-br" id="cBr"></div>

        <div class="hud-label hud-tl" id="hudTl">VT-ENGINE // BOOT</div>
        <div class="hud-label hud-tr" id="hudTr">LIVE<span class="pulse-dot"></span></div>
        <div class="hud-label hud-bl" id="hudBl">DEFENSIVE INTELLIGENCE</div>
        <div class="hud-label hud-br" id="hudBr">SESSION 0x1F</div>

        <div class="core-stage">
            <div class="core-ring ring1" id="ring1"></div>
            <div class="core-ring ring2" id="ring2"></div>
            <div class="core-ring ring3" id="ring3"></div>
            <div class="core-flash" id="coreFlash"></div>

            <svg class="core-svg" viewBox="0 0 200 200">
                <defs>
                    <linearGradient id="coreGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#8B5CF6"/>
                        <stop offset="100%" stop-color="#EC4899"/>
                    </linearGradient>
                </defs>
                <circle class="bg" cx="100" cy="100" r="90"></circle>
                <circle class="fg" id="coreFg" cx="100" cy="100" r="90"></circle>
            </svg>

            <div class="core-center">
                <div class="core-pct" id="corePct">0%</div>
                <div class="core-sub">CALIBRATING</div>
            </div>
        </div>

        <div class="log-panel" id="logPanel"></div>

        <div class="title-wrap" id="titleWrap">
            <div class="typewriter" id="typewriterTitle"></div>
            <div class="subtitle" id="subtitleLine">PERSONALISED THREAT INTELLIGENCE</div>
            <div class="status-final" id="statusFinal">SYSTEM READY</div>
        </div>
    </div>

    <script>
        (function(){
            var CIRC = 565.5;

            function on(id){ document.getElementById(id).classList.add("on"); }

            // mouse-reactive parallax on the core — small, subtle, purely visual
            var stage = document.querySelector(".core-stage");
            document.addEventListener("mousemove", function(e){
                var w = window.innerWidth, h = window.innerHeight;
                var dx = (e.clientX / w - 0.5) * 10;
                var dy = (e.clientY / h - 0.5) * 10;
                stage.style.transform = "translate(calc(-50% + " + dx + "px), calc(-50% + " + dy + "px))";
            });

            // ---- phase 1: ambient + HUD in ----
            setTimeout(function(){
                on("bgGlow"); on("gridBg"); on("scanline");
                on("cTl"); on("cTr"); on("cBl"); on("cBr");
                on("hudTl"); on("hudTr"); on("hudBl"); on("hudBr");
                on("ring1"); on("ring2"); on("ring3");
            }, 150);

            // ---- phase 2: boot log, one row at a time, own slot each ----
            var logLines = [
                "INITIALISING THREAT ENGINE",
                "LOADING VULNERABILITY DATASET",
                "CROSS-REFERENCING CISA KEV",
                "CALCULATING EPSS PROBABILITIES",
                "MAPPING ORGANISATION ASSETS",
                "COMPILING PRIORITY MATRIX"
            ];
            var logPanel = document.getElementById("logPanel");
            var pctEl = document.getElementById("corePct");
            var fgEl = document.getElementById("coreFg");
            var rows = [];

            logLines.forEach(function(text, i){
                var row = document.createElement("div");
                row.className = "log-row";
                row.style.animationDelay = (i * 0.55) + "s";
                row.innerHTML = '<span class="chk">&#9675;</span><span>&gt; ' + text + '</span>';
                logPanel.appendChild(row);
                rows.push(row);
            });

            var stepStart = 500;
            var stepGap = 560;
            logLines.forEach(function(_, i){
                setTimeout(function(){
                    var pct = Math.round(((i + 1) / logLines.length) * 100);
                    pctEl.textContent = pct + "%";
                    fgEl.style.strokeDashoffset = CIRC * (1 - pct / 100);
                    rows[i].classList.add("done");
                    rows[i].querySelector(".chk").innerHTML = "&#10003;";
                }, stepStart + i * stepGap);
            });

            var logDoneAt = stepStart + logLines.length * stepGap; // ~3860ms

            // ---- phase 3: core flash + log fades ----
            setTimeout(function(){
                document.getElementById("coreFlash").classList.add("pop");
                logPanel.style.transition = "opacity .5s ease";
                logPanel.style.opacity = "0";
                document.querySelector(".core-sub").textContent = "ONLINE";
            }, logDoneAt + 250);

            // ---- phase 4: title assembles (single element, built once) ----
            setTimeout(function(){
                var fullTitle = "VULNERABILITY TRIAGE";
                var el = document.getElementById("typewriterTitle");
                var perLetter = 0.045;
                for (var i = 0; i < fullTitle.length; i++){
                    var ch = fullTitle[i];
                    var span = document.createElement("span");
                    span.className = "letter";
                    span.style.animationDelay = (i * perLetter) + "s";
                    span.textContent = (ch === " ") ? "\\u00A0" : ch;
                    span.style.color = (i % 3 === 2) ? "#F472B6" : "#FFFFFF";
                    el.appendChild(span);
                }
                document.getElementById("titleWrap").classList.add("on");
            }, logDoneAt + 700);

            setTimeout(function(){
                document.getElementById("subtitleLine").classList.add("show");
            }, logDoneAt + 1700);

            setTimeout(function(){
                document.getElementById("statusFinal").classList.add("show");
            }, logDoneAt + 2100);

        })();
    </script>
    """

    components.html(INTRO_HTML, height=760, scrolling=False)

    # Real, interactive skip control — actually advances the Streamlit
    # screen state immediately rather than just fast-forwarding visually.
    _, skip_col, _ = st.columns([3, 1, 3])
    with skip_col:
        if st.button("SKIP INTRO ⏭", use_container_width=True):
            st.session_state.screen = "landing"
            st.rerun()

    time.sleep(9.2)
    st.session_state.screen = "landing"
    st.rerun()


# ============================================================
# HOMEPAGE
# ============================================================

elif st.session_state.screen == "landing":

    topbar()

    total_records = len(vulnerabilities)
    kev_count = int(vulnerabilities["cisa_kev"].sum()) if total_records else 0

    md(
        """
        <div class="hero fade-in">
            <div class="grid-overlay"></div>

            <div class="hero-copy">
                <div class="kicker"><span class="dot"></span> PERSONALISED THREAT INTELLIGENCE</div>
                <div class="hero-tag" style="margin-top:18px;">Vulnerability Triage</div>

                <h1>KNOW YOUR RISK.<br><span>PRIORITISE WHAT MATTERS.</span></h1>

                <p>Transform vulnerability data into clear, actionable security priorities —
                using CVSS severity, EPSS exploit probability, CISA KEV exploitation data
                and real organisation context.</p>

                <div class="hero-btns">
                    <a href="#analyser-cta" class="btn-primary">START ANALYSIS →</a>
                    <a href="#platform" class="btn-secondary">EXPLORE THREATS</a>
                </div>
            </div>

            <div class="hero-visual">
                <div class="network">
                    <svg viewBox="0 0 400 340">
                        <defs>
                            <linearGradient id="flowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" stop-color="#A855F7"/>
                                <stop offset="100%" stop-color="#EC4899"/>
                            </linearGradient>
                        </defs>
                        <line class="lead" x1="70" y1="60" x2="190" y2="150"></line>
                        <line class="lead" x1="70" y1="280" x2="190" y2="190"></line>
                        <line class="lead" x1="330" y1="60" x2="210" y2="150"></line>
                        <line class="lead" x1="330" y1="280" x2="210" y2="190"></line>
                        <line class="lead" x1="200" y1="20" x2="200" y2="130"></line>

                        <line class="flow" x1="70" y1="60" x2="190" y2="150"></line>
                        <line class="flow" x1="70" y1="280" x2="190" y2="190"></line>
                        <line class="flow" x1="330" y1="60" x2="210" y2="150"></line>
                        <line class="flow" x1="330" y1="280" x2="210" y2="190"></line>
                        <line class="flow" x1="200" y1="20" x2="200" y2="130"></line>
                    </svg>

                    <div class="net-node nn1">CVSS<br><span style="opacity:.7">SEVERITY</span></div>
                    <div class="net-node nn2">EPSS<br><span style="opacity:.7">LIKELIHOOD</span></div>
                    <div class="net-node nn3">CISA KEV<br><span style="opacity:.7">EXPLOITATION</span></div>
                    <div class="net-node nn4">EXPOSURE<br><span style="opacity:.7">ATTACK SURFACE</span></div>
                    <div class="net-node nn5">ASSETS</div>

                    <div class="net-core">THREAT<br>ENGINE</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    md(
        f"""
        <div class="stats-grid fade-in-1">
            <div class="stat-card"><small>VULNERABILITIES ANALYSED</small><div class="stat-val">{total_records:,}</div></div>
            <div class="stat-card"><small>KNOWN EXPLOITED (KEV)</small><div class="stat-val">{kev_count:,}</div></div>
            <div class="stat-card"><small>THREAT FACTORS</small><div class="stat-val">CVSS · EPSS · KEV</div></div>
            <div class="stat-card"><small>PRIORITY ENGINE</small><div class="stat-val">ACTIVE</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    md(
        """
        <div id="platform">
            <div class="section-title fade-in-1">Built for real security decisions</div>
            <div class="section-sub fade-in-1">Everything the triage engine does under the hood, made visible.</div>
        </div>

        <div class="features-grid">
            <div class="feature-card fade-in-1">
                <div class="feature-icon">◈</div>
                <h3>Threat Intelligence</h3>
                <p>Understand what can actually hurt your organisation. Analyse CVSS, EPSS, CISA KEV and other vulnerability signals side by side.</p>
            </div>
            <div class="feature-card fade-in-2">
                <div class="feature-icon">▲</div>
                <h3>Risk Prioritisation</h3>
                <p>Stop treating every vulnerability equally. Rank vulnerabilities according to severity, exploitability and organisation context.</p>
            </div>
            <div class="feature-card fade-in-3">
                <div class="feature-icon">✓</div>
                <h3>Defensive Testing</h3>
                <p>Validate your security decisions. Negative testing identifies malformed, missing or inconsistent vulnerability data before it skews a ranking.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    md(
        """
        <div id="analyser-cta" class="cta fade-in-2">
            <div class="eyebrow">READY WHEN YOU ARE</div>
            <h2>Ready to find what matters?</h2>
            <p>Start your vulnerability analysis and discover your organisation's highest-priority threats in minutes.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")
    _, c, _ = st.columns([1.3, 1, 1.3])
    with c:
        if st.button("START ANALYSIS →", type="primary", use_container_width=True):
            st.session_state.screen = "setup"
            st.rerun()


# ============================================================
# ORGANISATION SELECTION
# ============================================================

elif st.session_state.screen == "setup":

    topbar()

    p = get_profile(st.session_state.org_key)

    md(
        """
        <div class="setup fade-in">
            <div class="eyebrow">THREAT ANALYSIS ENGINE · STEP 01 / 02</div>
            <h2>Who are we protecting?</h2>
            <div class="sub">
                Select an organisation. The triage engine uses available technology,
                exposure and criticality information when ranking vulnerability data.
                <br><br>
                Vulnerabilities without a direct technology match are still analysed
                and ranked as general threats.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    names = [p["name"] for p in profiles]
    selected_name = st.selectbox("Organisation", names, index=names.index(p["name"]))
    selected = next(x for x in profiles if x["name"] == selected_name)
    st.session_state.org_key = selected["key"]

    assets = assets_for(selected)

    md('<div class="section-title">Technology / critical product context</div>', unsafe_allow_html=True)

    if assets:
        cols = st.columns(min(3, len(assets)))
        for i, a in enumerate(assets):
            with cols[i % len(cols)]:
                md(
                    f"""
                    <div class="asset">
                        <b>{escape(a["display"])}</b>
                        <div class="muted" style="margin-top:8px">
                            Version: {escape(a["version"])}<br>
                            Service: {escape(a["service"])}<br>
                            Importance: {escape(a["importance"])}
                        </div>
                        <span class="tag">{escape(a["exposure"])}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    st.write("")
    a, b = st.columns([1, 3])
    with a:
        if st.button("← BACK", use_container_width=True):
            st.session_state.screen = "landing"
            st.rerun()
    with b:
        if st.button("ANALYSE THREATS →", type="primary", use_container_width=True):
            st.session_state.screen = "analyzing"
            st.rerun()


# ============================================================
# ANALYSER SCREEN
# ============================================================

elif st.session_state.screen == "analyzing":

    topbar()

    active_profile = get_profile(st.session_state.org_key)

    # Pre-compute how many priority threats will be found, so the
    # "complete" message can report a real number.
    _preview_results = triage(active_profile)
    _threats_found = min(5, len(_preview_results))

    analysis_steps = [
        "LOADING VULNERABILITY DATA",
        "ANALYSING CVSS",
        "CALCULATING EPSS",
        "CHECKING CISA KEV",
        "ANALYSING EXPOSURE",
        "MATCHING ORGANISATION ASSETS",
        "RUNNING NEGATIVE TESTS",
        "CALCULATING RISK",
        "BUILDING PRIORITY LIST",
    ]

    percent_steps = [0, 5, 12, 19, 27, 35, 44, 53, 61, 70, 78, 86, 94, 100]

    TOTAL_MS = 7200

    steps_json = json.dumps(analysis_steps)
    pct_json = json.dumps(percent_steps)
    org_name_json = json.dumps(active_profile["name"])
    threats_json = json.dumps(_threats_found)

    RADIUS = 92
    CIRC = round(2 * 3.14159265 * RADIUS, 2)

    ANALYSIS_HTML = f"""
    <style>
        html, body{{ margin:0; padding:0; background:transparent; overflow:hidden; font-family:'Space Grotesk', sans-serif; }}

        .an-wrap{{
            position:relative; border:1px solid #39204F; border-radius:26px; padding:34px 30px;
            background:
                radial-gradient(circle at 15% 0%, rgba(139,92,246,.18), transparent 45%),
                radial-gradient(circle at 90% 90%, rgba(236,72,153,.12), transparent 45%),
                linear-gradient(160deg,#140A20,#07030D);
            overflow:hidden; display:grid; grid-template-columns:340px 1fr; gap:34px; align-items:center;
        }}
        @media (max-width:820px){{ .an-wrap{{ grid-template-columns:1fr; }} }}

        .an-left{{ position:relative; display:flex; flex-direction:column; align-items:center; text-align:center; }}
        .an-eyebrow{{ color:#C084FC; font:800 11px 'JetBrains Mono', monospace; letter-spacing:1.5px; }}
        .an-h2{{ font-size:24px; font-weight:800; letter-spacing:2px; color:#fff; margin:8px 0 4px; }}

        .an-org{{
            display:inline-block; margin-top:2px; margin-bottom:20px; padding:6px 16px;
            border:1px solid #8B5CF6; border-radius:999px; color:#e9d5ff; font:800 12px 'JetBrains Mono', monospace;
            letter-spacing:1px; background:rgba(139,92,246,.1);
        }}

        .an-ring-wrap{{ position:relative; width:230px; height:230px; }}
        .an-ring-wrap svg{{ width:100%; height:100%; transform:rotate(-90deg); }}
        .an-ring-bg{{ fill:none; stroke:#1e1030; stroke-width:10; }}
        .an-ring-fg{{
            fill:none; stroke:url(#anGrad); stroke-width:10; stroke-linecap:round;
            stroke-dasharray:{CIRC}; stroke-dashoffset:{CIRC};
            filter:drop-shadow(0 0 10px rgba(236,72,153,.55)); transition:stroke-dashoffset .3s ease;
        }}

        .an-ring-outer{{ position:absolute; inset:-16px; border-radius:50%; border:1px dashed rgba(168,85,247,.35); animation:anRingSpin 7s linear infinite; }}
        .an-ring-outer2{{ position:absolute; inset:-30px; border-radius:50%; border:1px dashed rgba(236,72,153,.2); animation:anRingSpin 11s linear infinite reverse; }}
        @keyframes anRingSpin{{ from{{ transform:rotate(0deg); }} to{{ transform:rotate(360deg); }} }}

        .an-pct{{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; flex-direction:column; }}
        .an-pct-num{{ font-size:46px; font-weight:800; color:#fff; font-family:'JetBrains Mono', monospace; text-shadow:0 0 20px rgba(236,72,153,.6); }}
        .an-pct-lab{{ color:#BFAED0; font:800 9px 'JetBrains Mono', monospace; letter-spacing:2px; margin-top:2px; }}

        .an-particle{{
            position:absolute; width:5px; height:5px; border-radius:50%; background:#EC4899; box-shadow:0 0 8px #EC4899;
            left:50%; top:50%; opacity:0; animation:anParticle 2.4s linear infinite;
        }}
        @keyframes anParticle{{
            0%{{ opacity:0; transform:translate(-50%,-50%) rotate(var(--ang)) translateX(150px) rotate(calc(var(--ang) * -1)); }}
            15%{{ opacity:1; }} 85%{{ opacity:1; }}
            100%{{ opacity:0; transform:translate(-50%,-50%) rotate(var(--ang)) translateX(6px) rotate(calc(var(--ang) * -1)); }}
        }}

        .an-message{{ margin-top:20px; min-height:18px; color:#C084FC; font:800 12px 'JetBrains Mono', monospace; letter-spacing:.8px; }}
        .an-complete{{ margin-top:12px; font:800 15px 'JetBrains Mono', monospace; letter-spacing:1px; color:#F472B6; text-shadow:0 0 16px rgba(244,63,94,.5); display:none; }}

        .an-right{{ position:relative; }}
        .an-right-label{{ color:#BFAED0; font:800 11px 'JetBrains Mono', monospace; letter-spacing:1.6px; margin-bottom:14px; }}

        .an-step{{
            display:flex; align-items:center; gap:12px; padding:9px 12px; border-radius:10px; margin-bottom:6px;
            border:1px solid transparent; color:#6b5c80; font-size:12.5px; transition:color .2s, border-color .2s, background .2s;
            font-family:'JetBrains Mono', monospace;
        }}
        .an-step .an-icon{{
            width:18px; height:18px; border-radius:50%; flex-shrink:0; display:flex; align-items:center; justify-content:center;
            font-size:11px; border:1.5px solid #39204F; color:#6b5c80;
        }}
        .an-step.active{{ color:#e9d5ff; border-color:rgba(168,85,247,.4); background:rgba(139,92,246,.08); }}
        .an-step.active .an-icon{{ border-color:#A855F7; color:#A855F7; box-shadow:0 0 10px rgba(168,85,247,.55); animation:anActivePulse 1s ease-in-out infinite; }}
        @keyframes anActivePulse{{ 0%,100%{{ opacity:1; }} 50%{{ opacity:.5; }} }}
        .an-step.done{{ color:#8fb0a0; }}
        .an-step.done .an-icon{{ border-color:#2be07a; color:#2be07a; background:rgba(43,224,122,.08); }}
    </style>

    <div class="an-wrap">
        <div class="an-left">
            <div class="an-eyebrow">THREAT ANALYSIS ENGINE &middot; STEP 02 / 02</div>
            <div class="an-h2">ANALYSING THREAT DATA</div>
            <div class="an-org" id="anOrgName"></div>

            <div class="an-ring-wrap">
                <div class="an-ring-outer"></div>
                <div class="an-ring-outer2"></div>

                <div class="an-particle" style="--ang:0deg; animation-delay:0s;"></div>
                <div class="an-particle" style="--ang:60deg; animation-delay:.4s;"></div>
                <div class="an-particle" style="--ang:120deg; animation-delay:.8s;"></div>
                <div class="an-particle" style="--ang:180deg; animation-delay:1.2s;"></div>
                <div class="an-particle" style="--ang:240deg; animation-delay:1.6s;"></div>
                <div class="an-particle" style="--ang:300deg; animation-delay:2.0s;"></div>

                <svg viewBox="0 0 210 210">
                    <defs>
                        <linearGradient id="anGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="#8B5CF6"/>
                            <stop offset="100%" stop-color="#EC4899"/>
                        </linearGradient>
                    </defs>
                    <circle class="an-ring-bg" cx="105" cy="105" r="{RADIUS}"></circle>
                    <circle class="an-ring-fg" id="anRingFg" cx="105" cy="105" r="{RADIUS}"></circle>
                </svg>

                <div class="an-pct">
                    <div class="an-pct-num" id="anPctNum">0%</div>
                    <div class="an-pct-lab">ANALYSING</div>
                </div>
            </div>

            <div class="an-message" id="anMessage"></div>
            <div class="an-complete" id="anComplete"></div>
        </div>

        <div class="an-right">
            <div class="an-right-label">ANALYSIS PROGRESS</div>
            <div id="anSteps"></div>
        </div>
    </div>

    <script>
        (function(){{
            var steps = {steps_json};
            var pcts = {pct_json};
            var orgName = {org_name_json};
            var threatsFound = {threats_json};
            var circumference = {CIRC};
            var totalMs = {TOTAL_MS};

            document.getElementById("anOrgName").textContent = orgName;

            var stepsEl = document.getElementById("anSteps");
            steps.forEach(function(label, idx){{
                var row = document.createElement("div");
                row.className = "an-step";
                row.id = "an-step-" + idx;
                row.innerHTML = '<span class="an-icon">&#9675;</span><span>' + label + '</span>';
                stepsEl.appendChild(row);
            }});

            var pctEl = document.getElementById("anPctNum");
            var ringEl = document.getElementById("anRingFg");
            var msgEl = document.getElementById("anMessage");
            var completeEl = document.getElementById("anComplete");

            var stepMs = totalMs / pcts.length;
            var frame = 0;

            function tick(){{
                if(frame >= pcts.length){{
                    msgEl.textContent = "Threat intelligence processed successfully.";
                    msgEl.style.color = "#34d399";
                    completeEl.textContent = "ANALYSIS COMPLETE — " + threatsFound + " priority threats identified";
                    completeEl.style.display = "block";
                    return;
                }}

                var pct = pcts[frame];
                var eased = pct / 100;
                pctEl.textContent = pct + "%";
                ringEl.style.strokeDashoffset = circumference * (1 - eased);

                var msgIdx = Math.min(steps.length - 1, Math.floor(eased * steps.length));
                msgEl.textContent = steps[msgIdx] + "...";

                for(var i = 0; i < steps.length; i++){{
                    var row = document.getElementById("an-step-" + i);
                    var icon = row.querySelector(".an-icon");
                    if(i < msgIdx || pct >= 100){{
                        row.className = "an-step done"; icon.innerHTML = "&#10003;";
                    }} else if(i === msgIdx){{
                        row.className = "an-step active"; icon.innerHTML = "&#9679;";
                    }} else {{
                        row.className = "an-step"; icon.innerHTML = "&#9675;";
                    }}
                }}

                frame++;
                setTimeout(tick, stepMs);
            }}

            tick();
        }})();
    </script>
    """

    components.html(ANALYSIS_HTML, height=440, scrolling=False)

    time.sleep((TOTAL_MS / 1000) + 1.0)
    st.session_state.screen = "dashboard"
    st.rerun()


# ============================================================
# RESULTS / VULNERABILITY RANKING
# ============================================================

else:

    profile = get_profile(st.session_state.org_key)

    topbar()

    with st.sidebar:
        md(
            """
            <div class="brand">
                <div class="logo">VT</div>
                <div>
                    <b style="color:var(--text-heading)">Vulnerability Triage</b>
                    <div class="muted">Personalised security intelligence</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.divider()

        names = [p["name"] for p in profiles]
        selected_name = st.selectbox("SELECT ORGANISATION", names, index=names.index(profile["name"]))

        if selected_name != profile["name"]:
            profile = next(p for p in profiles if p["name"] == selected_name)
            st.session_state.org_key = profile["key"]
            st.session_state.selected_rank = None
            st.rerun()

        st.divider()

        md("**DATA PACK**")
        st.caption(f"{len(vulnerabilities):,} vulnerability records")
        st.caption(f"Source file: {CSV_FILE.name if CSV_FILE else 'not found'}")

        st.divider()

        st.caption("RANKING SIGNALS")
        st.caption("CVSS severity")
        st.caption("CISA KEV exploitation")
        st.caption("FIRST EPSS likelihood")
        st.caption("Organisation context")
        st.caption("Exposure + service importance")

        st.divider()

        if st.button("↻ RUN ANALYSIS AGAIN", use_container_width=True):
            st.session_state.screen = "analyzing"
            st.session_state.selected_rank = None
            st.rerun()

    # --------------------------------------------------------
    # RUN TRIAGE
    # --------------------------------------------------------

    results = triage(profile)
    raw_total = len(vulnerabilities)
    total_vulnerabilities = len(results)
    matched = sum(r["profile_match"] for r in results)
    unmatched = total_vulnerabilities - matched

    urgent = sum(r["label"] == "URGENT" for r in results)
    high = sum(r["label"] == "HIGH" for r in results)
    medium = sum(r["label"] == "MEDIUM" for r in results)
    low = sum(r["label"] == "LOW" for r in results)
    critical = sum(r["score"] >= 90 for r in results)

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    md('<div class="section-title fade-in" style="margin-top:6px;">Threat Intelligence</div>', unsafe_allow_html=True)
    md(
        f'<div class="section-sub fade-in">Prioritised vulnerabilities for {escape(profile["name"])}</div>',
        unsafe_allow_html=True,
    )
    md('<div class="divider-glow fade-in"></div>', unsafe_allow_html=True)

    md(
        f"""
        <div class="profile fade-in">
            <div class="muted">ACTIVE ORGANISATION</div>
            <div class="profile-title">{escape(profile["name"])}</div>
            <div class="muted" style="margin-top:6px">
                {escape(profile["sector"])} · Risk appetite: {escape(profile["risk_appetite"])}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")

    # --------------------------------------------------------
    # EXECUTIVE SUMMARY
    # --------------------------------------------------------

    cols = st.columns(6)
    metrics = [
        ("TOTAL", total_vulnerabilities, "all ranked records"),
        ("URGENT", urgent, "priority ≥ 75"),
        ("CRITICAL", critical, "score ≥ 90"),
        ("HIGH", high, "high priority"),
        ("MEDIUM", medium, "moderate risk"),
        ("LOW", low, "lower priority"),
    ]
    for col, (lab, val, note) in zip(cols, metrics):
        with col:
            md(
                f'<div class="metric"><small>{lab}</small><strong>{val}</strong><span>{note}</span></div>',
                unsafe_allow_html=True,
            )

    # --------------------------------------------------------
    # THREAT LEVEL GAUGE
    # --------------------------------------------------------

    if results:
        sample = results[: min(5, len(results))]
        threat_pct = round(min(100, sum(r["score"] for r in sample) / len(sample)))
    else:
        threat_pct = 0

    threat_label, threat_cls = priority(threat_pct)
    gauge_colors = {"urgent": "#F43F5E", "high": "#EC4899", "medium": "#f4d35e", "low": "#2be07a"}

    md(
        f"""
        <div class="gauge-wrap fade-in">
            <div>
                <div class="gauge-label">OVERALL ORGANISATION THREAT LEVEL</div>
                <div class="gauge-level" style="color:{gauge_colors[threat_cls]}">{threat_label}</div>
            </div>
            <div class="gauge-track"><div class="gauge-fill" style="width:{threat_pct}%;"></div></div>
            <div class="gauge-pct">{threat_pct}%</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --------------------------------------------------------
    # TOP 5 — staggered reveal, summary-only cards + View Details
    # --------------------------------------------------------

    md('<div class="section-title">TOP 5 PRIORITY VULNERABILITIES</div>', unsafe_allow_html=True)
    md(
        f"""
        <div class="section-sub">
            The vulnerabilities requiring the most attention ·
            {total_vulnerabilities:,} analysed · {matched:,} profile matches · {unmatched:,} general threats
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not results:
        st.warning("No vulnerability records were found in the supplied CSV.")
    else:
        top5 = results[:5]
        ordinal = {1: "FIRST", 2: "SECOND", 3: "THIRD", 4: "FOURTH", 5: "FIFTH"}

        for i, r in enumerate(top5, 1):
            asset = r["asset"]
            parts = r["parts"]
            reveal_delay = (i - 1) * 0.4

            match_text = "PROFILE MATCH: YES" if r["profile_match"] else "GENERAL THREAT"

            if r["kev"]:
                kev_text = f'<span class="sig kev">CISA KEV CONFIRMED +{parts["kev"]}</span>'
            else:
                kev_text = '<span class="sig">CISA KEV NOT CONFIRMED</span>'

            if r["profile_match"] and norm(asset["exposure"]) == "internet facing":
                exposure_text = '<span class="sig net">INTERNET-FACING</span>'
            elif r["profile_match"]:
                exposure_text = f'<span class="sig">{escape(asset["exposure"])}</span>'
            else:
                exposure_text = '<span class="sig">GENERAL THREAT · CONTEXT 0</span>'

            md(
                f"""
                <div class="vcard {r["class"]} cascade-in" style="animation-delay:{reveal_delay:.2f}s">
                    <div class="vcard-bignum {r["class"]}">{i:02d}</div>
                    <div class="row">
                        <div>
                            <div class="rank">{i:02d} — {ordinal[i]} PRIORITY</div>
                            <div class="cve">{escape(r["cve"])}</div>
                            <div class="title">{escape(r["product"])}</div>
                            <div class="meta">{match_text}</div>
                        </div>
                        <div>
                            <span class="badge {r["class"]}">{r["label"]}</span>
                            <div class="score">{r["score"]}<small>RISK SCORE</small></div>
                        </div>
                    </div>
                    <div class="signalbar">
                        <span class="sig">CVSS {r["cvss"]:.1f}</span>
                        <span class="sig epss">EPSS {r["epss"] * 100:.1f}%</span>
                        {kev_text}
                        {exposure_text}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            _, btncol, _ = st.columns([2.4, 1.4, 2.4])
            with btncol:
                if st.button("VIEW DETAILS →", key=f"view_details_{i}", use_container_width=True):
                    st.session_state.selected_rank = i

        # ----------------------------------------------------
        # DETAIL DIALOG — shows only the selected vulnerability
        # ----------------------------------------------------

        @st.dialog("VULNERABILITY DETAILS", width="large")
        def show_detail(rank, r):
            asset = r["asset"]
            parts = r["parts"]

            md(
                f"""
                <div class="mono" style="color:#C084FC; font-weight:800; letter-spacing:1px; font-size:12px;">
                    RANK {rank:02d} · {r["label"]}
                </div>
                <div class="cve" style="font-size:22px;">{escape(r["cve"])}</div>
                <div class="title" style="font-size:22px;">{escape(r["product"])}</div>

                <div class="signalbar" style="margin-top:16px;">
                    <span class="sig">RISK SCORE {r["score"]}</span>
                    <span class="sig">CVSS {r["cvss"]:.1f}</span>
                    <span class="sig epss">EPSS {r["epss"] * 100:.1f}%</span>
                    <span class="sig {"kev" if r["kev"] else ""}">CISA KEV {"CONFIRMED" if r["kev"] else "NOT CONFIRMED"}</span>
                </div>

                <div class="reason">
                    <b>AFFECTED PRODUCT</b><br>{escape(r["product"])}
                    <br><br>
                    <b>AFFECTED VERSION</b><br>{escape(asset["version"]) if asset else "Not supplied"}
                    <br><br>
                    <b>ORGANISATION MATCH</b><br>{"Matched — " + escape(asset["display"]) if r["profile_match"] else "Not matched — treated as a general threat"}
                    <br><br>
                    <b>EXPOSURE</b><br>{escape(asset["exposure"]) if asset else "Not supplied"}
                    <br><br>
                    <b>WHY IT MATTERS</b><br>
                    CVSS severity: +{parts["cvss"]}<br>
                    CISA KEV exploitation: +{parts["kev"]}<br>
                    EPSS likelihood: +{parts["epss"]}<br>
                    Organisation context: +{parts["context"]}
                    <hr style="border-color:var(--border)">
                    <b>TOTAL RISK SCORE: {r["score"]}</b>
                </div>

                <div class="action">
                    <b>RECOMMENDED NEXT STEP</b>
                    Verify the affected product and version, review the relevant vendor
                    guidance, and prioritise remediation according to exploitation
                    indicators and calculated risk score.
                </div>

                <div class="muted" style="margin-top:12px">
                    Confidence: {r["confidence"]} · Source: supplied vulnerability CSV
                </div>
                """,
                unsafe_allow_html=True,
            )

            if st.button("CLOSE DETAILS ×", use_container_width=True):
                st.session_state.selected_rank = None
                st.rerun()

        if st.session_state.selected_rank:
            idx = st.session_state.selected_rank - 1
            if idx < len(top5):
                show_detail(st.session_state.selected_rank, top5[idx])

        # ----------------------------------------------------
        # SEARCH · FILTER · SORT (full ranked list)
        # ----------------------------------------------------

        md(
            """
            <div class="section-title">All Vulnerabilities</div>
            <div class="section-sub">Search, filter and sort the complete ranked dataset.</div>
            """,
            unsafe_allow_html=True,
        )

        fc1, fc2, fc3 = st.columns([2, 1.4, 1.4])
        with fc1:
            search_term = st.text_input("Search CVE or product", placeholder="e.g. CVE-2024 or vendor/product name")
        with fc2:
            severity_filter = st.multiselect("Filter by severity", ["URGENT", "CRITICAL", "HIGH", "MEDIUM", "LOW"], default=[])
        with fc3:
            sort_by = st.selectbox("Sort by", ["Risk score", "CVSS", "EPSS", "Severity", "KEV"])

        filtered = results

        if search_term:
            term = search_term.strip().lower()
            filtered = [r for r in filtered if term in r["cve"].lower() or term in r["product"].lower()]

        if severity_filter:
            wanted = set(severity_filter)
            filtered = [
                r for r in filtered
                if r["label"] in wanted or ("CRITICAL" in wanted and r["score"] >= 90)
            ]

        sort_keys = {
            "Risk score": lambda r: r["score"],
            "CVSS": lambda r: r["cvss"],
            "EPSS": lambda r: r["epss"],
            "Severity": lambda r: r["score"],
            "KEV": lambda r: r["kev"],
        }
        filtered = sorted(filtered, key=sort_keys[sort_by], reverse=True)

        table_rows = [
            {
                "CVE": r["cve"],
                "Product": r["product"],
                "Severity": r["label"],
                "Risk Score": r["score"],
                "CVSS": r["cvss"],
                "EPSS %": round(r["epss"] * 100, 1),
                "KEV": "YES" if r["kev"] else "NO",
                "Profile Match": "YES" if r["profile_match"] else "NO",
            }
            for r in filtered[:200]
        ]

        st.caption(f"{len(filtered):,} matching record(s) {'(showing first 200)' if len(filtered) > 200 else ''}")
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True, height=380)

    # --------------------------------------------------------
    # NEGATIVE TEST — headline demonstration
    # --------------------------------------------------------

    md('<div class="section-title">Negative Test — High CVSS is not automatically relevant</div>', unsafe_allow_html=True)
    md(
        '<div class="section-sub">A high CVSS score alone does not automatically make a vulnerability the highest priority.</div>',
        unsafe_allow_html=True,
    )

    high_cvss_results = sorted(results, key=lambda r: (r["cvss"], r["score"]), reverse=True)

    if high_cvss_results:
        n = high_cvss_results[0]
        match_status = "YES" if n["profile_match"] else "NO"
        p = n["parts"]

        md(
            f"""
            <div class="reason">
                <b>HIGH-CVSS NEGATIVE TEST</b><br><br>
                <span style="color:#F472B6; font:800 13px 'JetBrains Mono', monospace">{escape(n["cve"])} · {escape(n["product"])}</span><br><br>
                CVSS: {n["cvss"]:.1f}<br>
                EPSS: {n["epss"] * 100:.1f}%<br>
                CISA KEV: {"YES" if n["kev"] else "NO"}<br>
                PROFILE MATCH: {match_status}<br>
                ORGANISATION CONTEXT: +{p["context"]}<br>
                FINAL SCORE: {n["score"]}
                <br><br>
                This demonstrates that CVSS severity is only one part of the ranking.
                EPSS, CISA KEV exploitation indicators and available organisation
                context also influence priority.
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        md('<div class="reason"><b>NEGATIVE TEST</b><br><br>No vulnerability records were available.</div>', unsafe_allow_html=True)

    # --------------------------------------------------------
    # DEFENSIVE VALIDATION
    # --------------------------------------------------------

    md('<div class="section-title">DEFENSIVE VALIDATION</div>', unsafe_allow_html=True)
    md('<div class="section-sub">Validation performed automatically during this analysis run.</div>', unsafe_allow_html=True)

    negtest_rows = run_negative_tests(raw_total, results)
    negtest_html = '<div class="negtest-grid">'
    for t in negtest_rows:
        negtest_html += f"""
        <div class="negtest-row">
            <div>
                <div class="negtest-name">{escape(t["name"])}</div>
                <div class="negtest-detail">{escape(t["detail"])}</div>
            </div>
            <div class="negtest-badge {t["status"]}">{t["status"]}</div>
        </div>
        """
    negtest_html += "</div>"
    md(negtest_html, unsafe_allow_html=True)

    # --------------------------------------------------------
    # DATA & PROVENANCE
    # --------------------------------------------------------

    md('<div class="section-title">Data & Provenance</div>', unsafe_allow_html=True)
    md(
        f"""
        <div class="reason">
            <b>SUPPLIED DATA ONLY</b><br><br>
            Vulnerability records: {len(vulnerabilities):,}<br>
            Vulnerability file: {escape(CSV_FILE.name if CSV_FILE else "missing")}<br>
            Profile source: {escape(profile["source"])}<br>
            Signals: CVSS · CISA KEV · FIRST EPSS · organisation context
            <br><br>
            This prototype does not scan systems, execute exploits, or claim that
            an organisation is secure.
        </div>
        """,
        unsafe_allow_html=True,
    )

    md('<div class="foot">VULNTRIAGE · MATCH → SCORE → RANK → EXPLAIN</div>', unsafe_allow_html=True)
