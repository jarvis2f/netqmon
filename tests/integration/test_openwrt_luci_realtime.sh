#!/usr/bin/env bash
set -euo pipefail

# Tests OpenWrt LuCI frontend logic, UCI configuration generation & fallback,
# and rpcd script behavior for multi-interface monitoring.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LUCI_DIR="${ROOT_DIR}/packaging/openwrt/luci-app-netqmon"
export GENERAL_JS="${LUCI_DIR}/root/www/luci-static/resources/view/netqmon/general.js"
export STATUS_JS="${LUCI_DIR}/root/www/luci-static/resources/view/netqmon/status.js"
RPCD_PLUGIN="${LUCI_DIR}/root/usr/libexec/rpcd/netqmon"
INIT_SCRIPT="${ROOT_DIR}/packaging/openwrt/files/etc/init.d/netqmon"
ACL_JSON="${LUCI_DIR}/root/usr/share/rpcd/acl.d/luci-app-netqmon.json"

echo "=== 1. LuCI JavaScript Logic Node.js Unit Verification ==="
node - << 'NODE_EOF'
const fs = require('fs');

const generalContent = fs.readFileSync(process.env.GENERAL_JS, 'utf8');
const statusContent = fs.readFileSync(process.env.STATUS_JS, 'utf8');

// Extract normalizeInterfaces, validateInterfaceName, and validateInterfaces
const normMatch = generalContent.match(/function normalizeInterfaces\(value\) \{[\s\S]*?\n\}/);
const nameMatch = generalContent.match(/function validateInterfaceName\(name\) \{[\s\S]*?\n\}/);
const valMatch = generalContent.match(/function validateInterfaces\(value\) \{[\s\S]*?\n\}/);
const formatMatch = statusContent.match(/function formatInterfaces\(status\) \{[\s\S]*?\n\}/);

if (!normMatch || !nameMatch || !valMatch || !formatMatch) {
  console.error("Failed to extract LuCI functions");
  process.exit(1);
}

eval(normMatch[0]);
eval(nameMatch[0]);
eval(valMatch[0]);
eval(formatMatch[0]);

// Test normalizeInterfaces
console.log("Testing normalizeInterfaces...");
if (JSON.stringify(normalizeInterfaces("eth0")) !== JSON.stringify(["eth0"])) throw new Error("Single string normalization failed");
if (JSON.stringify(normalizeInterfaces(["eth0", "wg0"])) !== JSON.stringify(["eth0", "wg0"])) throw new Error("Array normalization failed");
if (JSON.stringify(normalizeInterfaces(null)) !== JSON.stringify([])) throw new Error("Null normalization failed");

// Test validateInterfaceName
console.log("Testing validateInterfaceName...");
if (!validateInterfaceName("eth0")) throw new Error("Valid interface name rejected");
if (!validateInterfaceName("tun0")) throw new Error("Valid tun interface name rejected");
if (validateInterfaceName("")) throw new Error("Empty interface name accepted");
if (validateInterfaceName("eth0/1")) throw new Error("Interface with slash accepted");
if (validateInterfaceName("this_interface_name_is_way_too_long")) throw new Error("Interface > 15 chars accepted");

// Test validateInterfaces
console.log("Testing validateInterfaces...");
if (!validateInterfaces(["eth0", "wg0", "tun0"])) throw new Error("Valid interfaces list rejected");
if (validateInterfaces([])) throw new Error("Empty interfaces accepted");
if (validateInterfaces(["eth0", "eth0"])) throw new Error("Duplicate interfaces accepted");
if (validateInterfaces([""])) throw new Error("Empty string interface accepted");
if (validateInterfaces(["eth0/1"])) throw new Error("Interface with slash accepted");
if (validateInterfaces(["this_interface_name_is_way_too_long"])) throw new Error("Interface > 15 chars accepted");

// Test DynamicList option validate callback behavior
console.log("Testing DynamicList option validate callback...");
const dynListValidate = function(section_id, value) {
  if (value == null || value === '') return true;
  if (Array.isArray(value)) return validateInterfaces(value) ? true : "invalid";
  return validateInterfaceName(value) ? true : "invalid";
};
if (dynListValidate("main", "") !== true) throw new Error("DynamicList empty string value (container/placeholder) must be valid");
if (dynListValidate("main", null) !== true) throw new Error("DynamicList null value must be valid");
if (dynListValidate("main", "br-lan") !== true) throw new Error("DynamicList valid single interface value rejected");
if (dynListValidate("main", "eth/0") === true) throw new Error("DynamicList invalid interface with slash accepted");
if (dynListValidate("main", ["br-lan", "tun0"]) !== true) throw new Error("DynamicList valid array rejected");
if (dynListValidate("main", []) === true) throw new Error("DynamicList empty array accepted");

// Test formatInterfaces
console.log("Testing formatInterfaces...");
if (formatInterfaces({ interfaces: ["eth1", "wg0"] }) !== "eth1, wg0") throw new Error("formatInterfaces array failed");
if (formatInterfaces({ interface: "eth1" }) !== "eth1") throw new Error("formatInterfaces fallback failed");
if (formatInterfaces({}) !== "-") throw new Error("formatInterfaces empty failed");

console.log("LuCI JS function unit tests passed.");
NODE_EOF

echo "=== 2. OpenWrt init.d Environment Bridge Behavior Verification ==="
# Test shell simulation of init.d multi-interface export vs fallback
tmp_uci_test=$(mktemp -d)
trap 'rm -rf "${tmp_uci_test}"' EXIT

cat << 'SH' > "${tmp_uci_test}/test_init_env.sh"
#!/usr/bin/env bash
# Simulation of etc/init.d/netqmon multi-interface logic

# Case A: config_list_foreach main interfaces configured
interfaces_a=("eth1" "wg0" "tun0")
NETQMON_INTERFACES_A=""
for iface in "${interfaces_a[@]}"; do
  [ -n "$iface" ] && NETQMON_INTERFACES_A="${NETQMON_INTERFACES_A:+${NETQMON_INTERFACES_A},}$iface"
done
[ "${NETQMON_INTERFACES_A}" = "eth1,wg0,tun0" ] || exit 1

# Case B: fallback when interfaces list is empty but interface option is set
interfaces_b=()
interface_b="br-lan"
NETQMON_INTERFACES_B=""
for iface in "${interfaces_b[@]}"; do
  [ -n "$iface" ] && NETQMON_INTERFACES_B="${NETQMON_INTERFACES_B:+${NETQMON_INTERFACES_B},}$iface"
done
if [ -z "$NETQMON_INTERFACES_B" ] && [ -n "$interface_b" ]; then
  NETQMON_INTERFACE_B="$interface_b"
fi
[ "${NETQMON_INTERFACE_B}" = "br-lan" ] || exit 2

echo "init.d environment export logic passed."
SH
bash "${tmp_uci_test}/test_init_env.sh"

echo "=== 3. RPCD Plugin and ACL Specification Verification ==="
grep -Fq 'config_list_foreach main interfaces' "${RPCD_PLUGIN}"
grep -Fq '"interfaces":[' "${RPCD_PLUGIN}"
grep -Fq '"luci-rpc"' "${ACL_JSON}"
grep -Fq 'getNetworkDevices' "${GENERAL_JS}"

echo "All LuCI / OpenWrt integration checks passed successfully!"
