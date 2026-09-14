#!/usr/bin/env python3
"""Assert OpenWrt capture results copied from the disposable test directory."""
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
disabled = json.loads((root / "diagnostics-false.json").read_text())["data"]["sampling"]
enabled = json.loads((root / "diagnostics-true.json").read_text())["data"]["sampling"]
assert disabled["configs"] and all(not c["enabled"] for c in disabled["configs"])
assert disabled["sample_bytes"] == disabled["packet_count"] == 0, disabled
assert disabled["network_bytes"] > 0 and disabled["new_flows"] >= 6, disabled
assert enabled["configs"] and all(c["enabled"] for c in enabled["configs"])
assert enabled["sampled_flows"] >= 6, enabled
assert 0 < enabled["sample_bytes"] <= enabled["sampled_flows"] * 4096, enabled
assert 0 < enabled["packet_count"] <= enabled["sampled_flows"] * 8, enabled
assert enabled["max_sample_bytes"] <= 4096, enabled
assert enabled["dpi_success_rate"] > 0, enabled
assert enabled["network_bytes"] > disabled["network_bytes"], enabled
for phase in ("false", "true"):
    log = (root / f"agent-{phase}.log").read_text()
    for version in (4, 6):
        assert f"flow delta ip={version} protocol=6" in log, (phase, version)
print(json.dumps({"disabled_network_bytes": disabled["network_bytes"],
                  "enabled_sampling": enabled}, indent=2))
print("OPENWRT_SAMPLE_ASSERTIONS_OK")
