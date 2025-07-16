import os
import yara
from core.alerts import alert
from core.quarantine import quarantine_file

YARA_RULES_DIR = "./yara_rules"

def compile_yara_rules():
    rules = {}
    if not os.path.exists(YARA_RULES_DIR):
        alert(f"YARA rules directory {YARA_RULES_DIR} does not exist; no rules loaded.", severity="WARNING")
        return rules

    for root, _, files in os.walk(YARA_RULES_DIR):
        for file in files:
            if file.endswith((".yar", ".yara")):
                path = os.path.join(root, file)
                try:
                    rules[file] = yara.compile(filepath=path)
                    alert(f"Loaded YARA rule: {file}", severity="INFO")
                except yara.SyntaxError as e:
                    alert(f"YARA syntax error in {file}: {e}", severity="WARNING")
    return rules

def scan_file_with_yara(yara_rules, file_path):
    matches = []
    for name, rule in yara_rules.items():
        try:
            with open(file_path, 'rb') as f:
                if rule.match(data=f.read()):
                    matches.append(name)
        except yara.Error as e:
            alert(f"YARA scan error with rule '{name}' on {file_path}: {e}", severity="WARNING")
        except Exception as e:
            alert(f"Error scanning {file_path} with {name}: {e}", severity="WARNING")
    return matches

def scan_and_quarantine(yara_rules, file_path, enable_quarantine):
    matches = scan_file_with_yara(yara_rules, file_path)
    if matches:
        alert(f"YARA matched: {','.join(matches)} on file {file_path}", severity="WARNING")
        if enable_quarantine:
            quarantine_file(file_path)
    else:
        alert(f"No YARA matches for {file_path}")
