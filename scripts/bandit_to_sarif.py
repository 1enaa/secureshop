import json
import sys

bandit_file = sys.argv[1]
sarif_file = sys.argv[2]

with open(bandit_file, "r", encoding="utf-8") as f:
    data = json.load(f)

sarif = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "bandit",
                    "informationUri": "https://bandit.readthedocs.io"
                }
            },
            "results": []
        }
    ]
}

for issue in data.get("results", []):
    sarif["runs"][0]["results"].append({
        "ruleId": issue.get("test_id"),
        "message": {"text": issue.get("issue_text")},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": issue.get("filename")
                    },
                    "region": {
                        "startLine": issue.get("line_number")
                    }
                }
            }
        ]
    })

with open(sarif_file, "w", encoding="utf-8") as f:
    json.dump(sarif, f, indent=2)

print("SARIF generated successfully")