#!/usr/bin/env python3
"""
MITRE ATT&CK Coverage Map Generator
Creates a MITRE Navigator layer JSON showing detection coverage from Sigma rules.
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Set

ROOT = Path(__file__).parent.parent
RULES_DIR = ROOT / "rules"
OUTPUT_FILE = ROOT / "mitre_coverage_layer.json"

# Technique metadata for labeling
TECHNIQUE_INFO = {
    "T1059.001": {"name": "PowerShell", "tactic": "execution"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "credential-access"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "persistence"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "privilege-escalation"},
}

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact"
]

TACTIC_COLORS = {
    "execution": "#ff6b6b",
    "credential-access": "#4ecdc4",
    "persistence": "#ffe66d",
    "privilege-escalation": "#ffe66d",
    "defense-evasion": "#a855f7",
    "initial-access": "#06b6d4",
    "discovery": "#84cc16",
    "lateral-movement": "#f97316",
    "collection": "#ec4899",
    "command-and-control": "#6366f1",
    "exfiltration": "#14b8a6",
    "impact": "#ef4444",
}


def extract_techniques_from_rule(rule_path: Path) -> List[str]:
    """Extract MITRE technique IDs from a Sigma rule's tags."""
    techniques = []
    try:
        content = rule_path.read_text()
        # Find all attack.tXXXX.XXX patterns
        matches = re.findall(r'attack\.t(\d{4}\.\d{3})', content, re.IGNORECASE)
        for m in matches:
            techniques.append(f"T{m}")
    except Exception:
        pass
    return techniques


def generate_layer(rules_dir: Path) -> Dict:
    """Generate MITRE Navigator layer JSON."""
    technique_scores: Dict[str, Dict[str, float]] = {}  # technique -> {tactic: score}

    for rule_file in rules_dir.glob("*.yml"):
        techniques = extract_techniques_from_rule(rule_file)
        for tech in techniques:
            info = TECHNIQUE_INFO.get(tech, {"name": tech, "tactic": "unknown"})
            tactic = info["tactic"]
            if tech not in technique_scores:
                technique_scores[tech] = {}
            technique_scores[tech][tactic] = technique_scores[tech].get(tactic, 0) + 1

    # Build layer
    techniques = []
    for tech_id, tactic_scores in technique_scores.items():
        info = TECHNIQUE_INFO.get(tech_id, {"name": tech_id, "tactic": "unknown"})
        for tactic, score in tactic_scores.items():
            color = TACTIC_COLORS.get(tactic, "#888888")
            techniques.append({
                "techniqueID": tech_id,
                "tactic": tactic,
                "score": min(score, 10),  # Cap at 10 for color intensity
                "color": color,
                "comment": f"Covered by {score} rule(s)",
                "enabled": True,
                "metadata": [],
                "links": [
                    f"https://attack.mitre.org/techniques/{tech_id}/",
                ],
                "showSubtechniques": True,
            })

    layer = {
        "name": "SOC Lab Detection Coverage",
        "version": "4.5",
        "domain": "mitre-enterprise",
        "description": "Detection coverage map generated from Sigma rules in soc-lab/detection/rules/",
        "filters": {
            "platforms": ["windows", "linux", "macos", "network", "cloud", "office-365", "saas", "iaas", "google-workspace", "azure-ad"],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ffebee", "#ef5350"],
            "minValue": 0,
            "maxValue": 10,
        },
        "legendItems": [
            {"label": "No coverage", "color": "#ffffff"},
            {"label": "Low coverage (1 rule)", "color": "#ffebee"},
            {"label": "High coverage (3+ rules)", "color": "#ef5350"},
        ],
        "metadata": [
            {"name": "rules_directory", "value": str(rules_dir.relative_to(ROOT.parent))},
            {"name": "generator", "value": "detection/scripts/coverage_map.py"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#fafafa",
        "selectSubtechniquesWithParent": True,
    }
    return layer


def main():
    print(f"[+] Scanning rules in {RULES_DIR}")
    layer = generate_layer(RULES_DIR)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(layer, f, indent=2)
    print(f"[+] Layer saved to {OUTPUT_FILE}")
    print(f"[+] Techniques covered: {len(layer['techniques'])}")
    for tech in layer["techniques"]:
        print(f"    {tech['techniqueID']} ({tech['tactic']}) - score: {tech['score']}")
    print(f"\n[+] Open in MITRE Navigator: https://mitre-attack.github.io/attack-navigator/")
    print(f"    Drag & drop {OUTPUT_FILE.name} onto the page")


if __name__ == "__main__":
    main()