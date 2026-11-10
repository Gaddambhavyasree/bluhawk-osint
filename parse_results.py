import json
from collections import defaultdict

with open("bluecloudsoftech_passive.json", "r", encoding="utf-8") as f:
    report = json.load(f)

validated_by_source = defaultdict(list)
for a in report["validated_assets"]:
    for origin in a["origin"]:
        validated_by_source[origin].append(a["hostname"])

leads_by_source = defaultdict(list)
for lead in report["unverified_leads"]:
    for origin in lead["origin"]:
        leads_by_source[origin].append(lead["hostname"])

all_sources = sorted(set(list(validated_by_source.keys()) + list(leads_by_source.keys())))

print("=== PER-SOURCE BREAKDOWN ===")
print()

for source in all_sources:
    v = validated_by_source.get(source, [])
    leads = leads_by_source.get(source, [])
    total = len(v) + len(leads)
    print(f"--- {source.upper()} ({total} names) ---")
    if v:
        print(f"  VALIDATED ({len(v)}): {sorted(v)}")
    if leads:
        print(f"  UNVERIFIED ({len(leads)}): {sorted(leads)[:20]}" + ("..." if len(leads) > 20 else ""))
    print()

print(f"Total validated: {len(report['validated_assets'])}")
print(f"Total unverified leads: {len(report['unverified_leads'])}")
print(f"New subdomains count: {report.get('new_subdomains_count', 0)}")
print()
print("=== VALIDATED TREE ===")
for line in report["tree"]:
    print(line)
