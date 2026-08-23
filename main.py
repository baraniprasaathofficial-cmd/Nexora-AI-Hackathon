"""
Personalised Vulnerability Triage — CLI entry point (v2).

Usage:
    python main.py --list-orgs
    python main.py --org ORG-001
    python main.py --org ORG-003 --negative-test
    python main.py --compare ORG-001 ORG-002
    python main.py --validate         # re-runs the gold_set.csv self-check
"""

import argparse

from engine import (
    load_vulnerabilities, load_profiles, get_profile, run_triage,
    validate_against_gold_set,
)

DATA_DIR = "data"
VULN_CSV = f"{DATA_DIR}/vulnerabilities.csv"
PROFILES_JSON = f"{DATA_DIR}/profiles.json"


def print_card(rank, card):
    print(f"\n#{rank}  [{card['priority']}]  score {card['score']}  —  {card['cve_id']}  ({card['product']})")
    print(f"    {card['title']}")
    print("    Why it matters:")
    for line in card["why_it_matters_detail"]:
        print(f"      - {line}")
    print(f"    Next step: {card['next_step']}")
    print(f"    Confidence: {card['confidence']} ({card['confidence_reason']})")
    print(f"    Source: {card['source']}")


def print_top5(profile, results):
    w = profile["weight_modifiers"]
    print("\n" + "=" * 82)
    print(f"TOP {len(results)} FOR: {profile['name']}  ({profile['sector']}, risk appetite: {profile['risk_appetite']})")
    print(f"Weighting: CVSS {w['cvss_weight']:.0%} | KEV {w['cisa_kev_weight']:.0%} | EPSS {w['first_epss_weight']:.0%}")
    print(f"Critical assets: {', '.join(profile['critical_products'])}")
    print("=" * 82)
    if not results:
        print("\nNothing matched this profile in the supplied data.")
        return
    for i, card in enumerate(results, start=1):
        print_card(i, card)


def print_negative_test(negative_candidates):
    print("\n" + "-" * 82)
    print("REQUIRED NEGATIVE TEST — high-CVSS (>=9.0) items that did NOT make the top 5")
    print("-" * 82)
    if not negative_candidates:
        print("No high-CVSS item was excluded from the top 5 for this profile.")
        return
    for card in negative_candidates:
        print(f"\n{card['cve_id']} ({card['product']}) — CVSS {card['raw']['cvss']}/10, "
              f"KEV={'Yes' if card['raw']['kev'] else 'No'}, EPSS {card['raw']['epss']:.2f}")
        print(f"  Final score: {card['score']} ({card['priority']}) — ranked outside the top 5")
        print("  Why: " + "; ".join(card["why_it_matters"]))
        if not card["is_critical_asset"]:
            print("  This product is NOT on this organisation's critical asset list, "
                  "and this org's own weighting formula doesn't rate it high enough on "
                  "the signals it cares about — high severity alone isn't enough.")


def run_for_org(profiles, vulns, org_id, show_negative_test=False):
    profile = get_profile(profiles, org_id)
    top5, negative_candidates = run_triage(vulns, profile, top_n=5)
    print_top5(profile, top5)
    if show_negative_test:
        print_negative_test(negative_candidates)
    return top5


def main():
    parser = argparse.ArgumentParser(description="Personalised Vulnerability Triage")
    parser.add_argument("--org", help="org_id to run (e.g. ORG-001)")
    parser.add_argument("--compare", nargs=2, metavar=("ORG_1", "ORG_2"),
                         help="Show top 5 for two organisations side by side")
    parser.add_argument("--negative-test", action="store_true",
                         help="Also show the required high-CVSS negative test")
    parser.add_argument("--list-orgs", action="store_true", help="List available organisation ids")
    parser.add_argument("--validate", action="store_true", help="Re-run the gold_set.csv self-check")
    args = parser.parse_args()

    if args.validate:
        validate_against_gold_set(DATA_DIR)
        return

    vulns = load_vulnerabilities(VULN_CSV)
    profiles = load_profiles(PROFILES_JSON)

    if args.list_orgs:
        for p in profiles:
            print(f"{p['org_id']:10s} {p['name']} ({p['sector']})")
        return

    if args.compare:
        for oid in args.compare:
            run_for_org(profiles, vulns, oid, show_negative_test=args.negative_test)
        return

    if args.org:
        run_for_org(profiles, vulns, args.org, show_negative_test=args.negative_test)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
