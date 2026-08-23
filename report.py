"""
Generates a non-technical-friendly HTML report for one organisation's top 5.

Usage:
    python report.py --org ORG-001
    python report.py --org ORG-001 --out bank_report.html
"""

import argparse
import html

from engine import load_vulnerabilities, load_profiles, get_profile, run_triage

PRIORITY_COLORS = {
    "URGENT": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#7f8c8d",
}

CARD_TEMPLATE = """
<div class="card">
  <div class="priority-bar" style="background:{color}">{priority}  ·  score {score}{crit_badge}</div>
  <h2>{title}</h2>
  <p class="meta"><strong>{cve_id}</strong> &nbsp;|&nbsp; {product}</p>
  <h4>Why it matters</h4>
  <ul>{why_items}</ul>
  <h4>Next step</h4>
  <p class="next-step">{next_step}</p>
  <p class="confidence">Confidence: <strong>{confidence}</strong> &mdash; {confidence_reason}</p>
  <p class="source">Source: {source}</p>
</div>
"""

PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Triage — {org_name}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#f4f6f8; margin:0; padding:2rem; color:#222; }}
  .header {{ max-width:800px; margin:0 auto 2rem; }}
  .header h1 {{ margin-bottom:0.2rem; }}
  .header p {{ color:#555; margin-top:0.2rem; }}
  .header .weights {{ font-size:0.85rem; color:#777; }}
  .card {{ max-width:800px; margin:0 auto 1.5rem; background:#fff; border-radius:10px; box-shadow:0 1px 4px rgba(0,0,0,0.12); overflow:hidden; }}
  .priority-bar {{ color:#fff; font-weight:700; padding:0.5rem 1.2rem; letter-spacing:0.05em; }}
  .crit-badge {{ background:rgba(255,255,255,0.25); border-radius:4px; padding:0.1rem 0.5rem; margin-left:0.6rem; font-size:0.8rem; }}
  .card h2 {{ margin:1rem 1.2rem 0.3rem; font-size:1.15rem; }}
  .card .meta {{ margin:0 1.2rem 0.8rem; color:#555; font-size:0.9rem; }}
  .card h4 {{ margin:0.9rem 1.2rem 0.3rem; font-size:0.85rem; text-transform:uppercase; color:#888; }}
  .card ul {{ margin:0 1.2rem 0.6rem 2rem; padding:0; font-size:0.92rem; }}
  .next-step {{ margin:0 1.2rem 0.8rem; font-weight:600; }}
  .confidence {{ margin:0 1.2rem 0.4rem; font-size:0.85rem; color:#444; }}
  .source {{ margin:0 1.2rem 1rem; font-size:0.78rem; color:#999; }}
  .no-match {{ max-width:800px; margin:2rem auto; text-align:center; color:#777; }}
</style>
</head>
<body>
  <div class="header">
    <h1>Top {n} for {org_name}</h1>
    <p>{sector} &nbsp;|&nbsp; Risk appetite: {risk_appetite}</p>
    <p class="weights">Weighting: CVSS {cvss_w:.0%} &nbsp;|&nbsp; KEV {kev_w:.0%} &nbsp;|&nbsp; EPSS {epss_w:.0%}
       &nbsp;&nbsp;·&nbsp;&nbsp; Critical assets: {critical_products}</p>
  </div>
  {cards}
</body>
</html>
"""


def render_card(card):
    why_items = "".join(f"<li>{html.escape(d)}</li>" for d in card["why_it_matters_detail"])
    crit_badge = '<span class="crit-badge">CRITICAL ASSET</span>' if card["is_critical_asset"] else ""
    return CARD_TEMPLATE.format(
        color=PRIORITY_COLORS.get(card["priority"], "#555"),
        priority=card["priority"],
        score=card["score"],
        crit_badge=crit_badge,
        title=html.escape(card["title"]),
        cve_id=card["cve_id"],
        product=html.escape(card["product"]),
        why_items=why_items,
        next_step=html.escape(card["next_step"]),
        confidence=card["confidence"],
        confidence_reason=html.escape(card["confidence_reason"]),
        source=card["source"],
    )


def render_report(profile, results):
    w = profile["weight_modifiers"]
    if not results:
        cards_html = '<p class="no-match">Nothing matched this profile in the supplied data.</p>'
    else:
        cards_html = "".join(render_card(c) for c in results)
    return PAGE_TEMPLATE.format(
        org_name=html.escape(profile["name"]),
        n=len(results),
        sector=profile["sector"],
        risk_appetite=profile["risk_appetite"],
        cvss_w=w["cvss_weight"],
        kev_w=w["cisa_kev_weight"],
        epss_w=w["first_epss_weight"],
        critical_products=html.escape(", ".join(profile["critical_products"])),
        cards=cards_html,
    )


def main():
    parser = argparse.ArgumentParser(description="Generate an HTML triage report for one organisation")
    parser.add_argument("--org", required=True, help="org_id, e.g. ORG-001")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    vulns = load_vulnerabilities(f"{args.data_dir}/vulnerabilities.csv")
    profiles = load_profiles(f"{args.data_dir}/profiles.json")
    profile = get_profile(profiles, args.org)

    top5, _ = run_triage(vulns, profile, top_n=5)
    html_out = render_report(profile, top5)

    out_path = args.out or f"{args.org}_report.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
