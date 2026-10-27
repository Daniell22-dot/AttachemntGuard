import os

def scan_with_yara(path: str, rules_dir: str) -> list:
    try:
        import yara
    except Exception as e:
        return [{'error': f'yara_unavailable: {e}'}]
    
    matches = []
    try:
        rule_files = []
        for root, dirs, files in os.walk(rules_dir):
            for fn in files:
                if fn.endswith(('.yar', '.yara')):
                    rule_files.append(os.path.join(root, fn))
        if not rule_files:
            return matches
        # compile all rules
        filepaths = {os.path.basename(f).replace('.yar','').replace('.yara',''): f for f in rule_files}
        rules = yara.compile(filepaths=filepaths)
        m = rules.match(path)
        for match in m:
            matches.append({
                'rule': match.rule,
                'tags': match.tags,
                'meta': match.meta,
                'strings': [(s.identifier, s.instances[0].offset if s.instances else None) for s in match.strings]
            })
        return matches
    except Exception as e:
        return [{'error': str(e)}]
