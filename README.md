# Personalised Vulnerability Triage

Turns public vulnerability data into a ranked top 5 that a non-expert at a
small organisation can understand and act on. Built against the **real
organiser-supplied starter pack** (`vulnerabilities.csv`, `profiles.json`,
`gold_set.csv`).

## Quick start (under 5 minutes)

```bash
# 1. See the available organisations
python main.py --list-orgs

# 2. Get a top 5 for one organisation
python main.py --org ORG-001

# 3. Include the required negative test (high-CVSS item that misses the top 5)
python main.py --org ORG-003 --negative-test

# 4. Prove personalisation by comparing two organisations side by side
python main.py --compare ORG-001 ORG-002

# 5. Re-run the scoring formula against gold_set.csv to confirm it matches
python main.py --validate

# 6. Generate a non-technical HTML report for the live demo
python report.py --org ORG-001
# open ORG-001_report.html in a browser
```

Pure Python standard library — no `pip install`, no API key, no internet
connection needed.

## ⚠️ This dataset's schema is different from the brief's illustrative example

The brief's Appendix A shows a vendor/product/version-based schema. **The
actual starter pack you were given uses a different, simpler model** — this
prototype is built against the real files, not the illustrative example.

| Real `vulnerabilities.csv` | Real `profiles.json` |
|---|---|
| `cve_id`, `product_name`, `cvss_base_score`, `cisa_kev`, `first_epss` | `org_id`, `name`, `sector`, `risk_appetite`, `weight_modifiers` (cvss/kev/epss weights per org), `critical_products` (list of product names) |

Key differences from the illustrative schema:
- **No vendor or version fields at all.** There's nothing to do a
  vendor/version match against, so there's no "product not used" /
  "version not affected" exclusion step in this dataset.
- **Every organisation is exposed to the same 6 products.** The dataset
  has no per-org technology inventory — instead, `critical_products` tells
  you which of those 6 are business-critical to a given org.
- **The organiser gave us explicit weights**, not raw signals to invent
  our own weighting for. Each org's `weight_modifiers` says exactly how
  much *they* personally value CVSS vs KEV vs EPSS — this **is** the
  personalisation mechanism.

## Sources

| Source | What it provides | Column in `vulnerabilities.csv` |
|---|---|---|
| [NVD](https://nvd.nist.gov/developers/vulnerabilities) | Technical severity | `cvss_base_score` |
| [CISA KEV](https://www.cisa.gov/resources-tools/resources/kev-catalog) | Confirmed real-world exploitation | `cisa_kev` |
| [FIRST EPSS](https://www.first.org/epss/using-epss) | 30-day exploitation probability | `first_epss` |

## The scoring formula — reverse-engineered and validated against `gold_set.csv`

`gold_set.csv` gives practitioner rankings for 5 CVEs against 2 of the 3
organisations (`practitioner_rank_bank`, `practitioner_rank_startup`).
I derived a formula and confirmed it reproduces **all 10 known rankings
exactly** — run `python main.py --validate` to see this for yourself:

```
base  = 100 * ( cvss_weight  × (cvss_base_score / 10)
              + kev_weight   × (1 if cisa_kev else 0)
              + epss_weight  × first_epss )

total = round(base) + (30 if product_name in org's critical_products else 0)
```

Where `cvss_weight`, `kev_weight`, `epss_weight` come directly from that
organisation's own `weight_modifiers` in `profiles.json`.

**Why a flat +30 bonus for critical assets, not a multiplier:** I tested
both. A multiplier had to be tuned so large (~1.4×) to correctly rank the
startup's Cloud Database Engine above their own non-critical-but-high-KEV
Core Banking Framework row that it started distorting other rankings. A
flat +30 additive bonus reproduced all 10 gold-set ranks exactly with no
further tuning — see the "Why it matters" line in every result card,
labelled `Business-critical asset (+30)`, so the bonus is always visible,
never hidden inside a black-box multiplier.

This satisfies the brief's "at least 3 visible signals" requirement with
room to spare: CVSS, KEV, EPSS, and asset criticality are all shown as
separate, individually-weighted line items on every card.

## The required negative test

Run `python main.py --org ORG-003 --negative-test`. `CVE-2024-1851`
(Embedded IoT Gateway) has a **perfect CVSS 10.0** and is even on the
Municipal Utility Provider's critical asset list — but it isn't KEV-listed
and has a very low EPSS score (0.02). It scores 80 and misses the org's
top 5, which is filled with lower-CVSS items that are either confirmed
exploited (KEV) or have much higher exploitation probability. This is a
clean demonstration that this engine is not just sorting by severity — a
maximum-severity item is deliberately outranked because the organisation's
own weighting formula (50% CVSS / 40% KEV / 10% EPSS) still needs more than
raw severity to earn urgency.

## Pipeline

```
LOAD -> SCORE -> RANK -> EXPLAIN -> PRESENT
```

1. **LOAD** (`engine.load_vulnerabilities`, `engine.load_profiles`)
2. **SCORE** (`engine.score_vulnerability`) — the formula above, with every
   contributing point kept in a visible, labelled list
3. **RANK** (`engine.run_triage`) — deduplicates by `(cve_id, product_name)`
   (this dataset reuses CVE IDs across different products with different
   scores, so both fields are needed as the unique key), sorts by score,
   takes the top 5, and separately surfaces any CVSS ≥ 9.0 item that missed
   the cut for the negative test
4. **EXPLAIN** (`engine.build_result_card`) — plain-language title,
   contributing factors, one safe next step, a confidence level with reason
5. **PRESENT** — `main.py` (terminal, for fast iteration) and `report.py`
   (HTML, for the live demo)

## Assumptions

- Because there's no per-org technology inventory or version data, "not
  used by this org" isn't a possible outcome in this dataset — every
  product applies to every org, differentiated by weight and criticality
  instead of inclusion/exclusion.
- `(cve_id, product_name)` is treated as the unique key, since the same
  CVE ID legitimately appears against multiple products with different
  scores in this dataset (541 rows, 540 unique products entries — one
  header row).
- Confidence level is derived from KEV status and EPSS (not from a version
  match, since there's no version data): KEV-listed = High confidence;
  EPSS ≥ 0.3 = Medium; otherwise Low.

## Limitations

- This dataset has no `reference_url`, `published_date`, or
  `source_snapshot_date` field, so result cards cite the CVE ID and the
  three named sources (NVD/KEV/EPSS) rather than a direct link — a judge
  can look up any CVE ID in those catalogs to spot-check a claim.
- The +30 critical-asset bonus is a flat constant tuned against 2 of 3
  organisations' gold data (the bank and the startup) — the Municipal
  Utility Provider has no gold-set rows to validate against, so its
  ranking uses the same formula but is unverified against ground truth.
- No AI/LLM phrasing is used — every sentence is template-based directly
  from record fields and each org's own declared weights, so nothing is
  invented, at the cost of less varied language.

## Project structure

```
vuln-triage/
├── data/
│   ├── vulnerabilities.csv   # organiser-provided
│   ├── profiles.json         # organiser-provided
│   └── gold_set.csv          # organiser-provided
├── engine.py                  # score, rank, explain + gold_set self-validation
├── main.py                    # CLI: top 5, negative test, compare, validate
├── report.py                  # HTML report generator for the demo
└── README.md
```
