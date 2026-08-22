import json
from persisthunt.findings import Finding, FindingCollection, Severity

def main():
    collection = FindingCollection()

    # 1 INFO finding
    collection.add(Finding(
        id="PH-TEST-001", category="general", severity=Severity.INFO,
        title="Info level finding", description="Just some info."
    ))

    # 1 LOW finding
    collection.add(Finding(
        id="PH-TEST-002", category="general", severity=Severity.LOW,
        title="Low level finding", description="A low severity issue."
    ))

    # 1 MEDIUM finding
    collection.add(Finding(
        id="PH-TEST-003", category="general", severity=Severity.MEDIUM,
        title="Medium level finding", description="A medium severity issue."
    ))

    # 1 HIGH finding
    collection.add(Finding(
        id="PH-TEST-004", category="systemd", severity=Severity.HIGH,
        title="High level finding", description="A high severity issue.",
        evidence="ExecStart=/tmp/malicious"
    ))

    # 1 CRITICAL finding
    collection.add(Finding(
        id="PH-TEST-005", category="cron", severity=Severity.CRITICAL,
        title="Critical level finding", description="A critical severity issue."
    ))

    print("--- Stored Findings ---")
    print(f"Total stored: {collection.count()} (Expected: 5)")

    print("\n--- Filtering by Severity (HIGH) ---")
    highs = collection.by_severity(Severity.HIGH)
    print(f"High severity findings: {len(highs)} (Expected: 1)")
    print(f"ID: {highs[0].id}")

    print("\n--- Filtering by Category (systemd) ---")
    sys_cats = collection.by_category("systemd")
    print(f"Systemd findings: {len(sys_cats)} (Expected: 1)")
    
    print("\n--- Statistics ---")
    stats = collection.severity_counts()
    for k, v in stats.items():
        print(f"{k}: {v}")

    print("\n--- Dictionary Serialization ---")
    dicts = collection.to_dict()
    print(f"List length: {len(dicts)}")
    print(f"First element title: {dicts[0]['title']}")

    print("\n--- JSON Serialization ---")
    json_out = json.dumps(dicts, indent=2)
    print(json_out)

if __name__ == "__main__":
    main()
