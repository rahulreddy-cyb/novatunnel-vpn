from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]

print("=== DASHBOARD DEFAULT SECURITY TEST ===")

# Test 1: Example configuration
with (ROOT / "configs/server.toml.example").open("rb") as f:
    config = tomllib.load(f)

dashboard = config["dashboard"]

assert dashboard["enabled"] is False
assert dashboard["host"] == "127.0.0.1"
assert dashboard["port"] == 8080

print("PASS 1: Example dashboard disabled and localhost-only")

# Test 2: Installer-generated configuration
installer = (ROOT / "install.sh").read_text()

sections = re.findall(
    r"(?ms)^\[dashboard\][ \t]*\n(.*?)(?=^EOF[ \t]*$|\Z)",
    installer,
)

assert len(sections) == 1, "Expected one installer dashboard section"

section = sections[0]

expected = {
    "enabled": "false",
    "host": '"127.0.0.1"',
    "port": "8080",
}

for key, value in expected.items():
    matches = re.findall(
        rf"(?m)^{re.escape(key)}[ \t]*=[ \t]*([^#\n]+)",
        section,
    )
    assert len(matches) == 1
    assert matches[0].strip() == value, f"Unsafe {key} default"

print("PASS 2: Installer dashboard disabled and localhost-only")
print("=== DASHBOARD DEFAULT TESTS COMPLETE ===")
