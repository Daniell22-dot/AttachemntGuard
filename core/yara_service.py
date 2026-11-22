import os
from pathlib import Path
from typing import List

try:
    import yara
except ImportError:
    yara = None


def scan_with_yara(path, rules_dir) -> List[dict]:
    if yara is None:
        return [{"error": "yara_unavailable: yara-python is not installed"}]

    rule_files = []
    for root, _, files in os.walk(str(rules_dir)):
        for name in files:
            if name.endswith((".yar", ".yara")):
                rule_files.append(os.path.join(root, name))
    if not rule_files:
        return []

    try:
        filepaths = {
            Path(path).stem: path for path in rule_files
        }
        rules = yara.compile(filepaths=filepaths)
        matches = rules.match(str(path))
        results = []
        for match in matches:
            results.append({
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta,
                "strings": [
                    (string.identifier, string.instances[0].offset if string.instances else None)
                    for string in match.strings
                ],
            })
        return results
    except Exception as exc:
        return [{"error": str(exc)}]
