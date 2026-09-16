#!/usr/bin/env python3
"""Assert stored metadata after openwrt_recognition.sh; never reads packet payloads."""
import json
import sqlite3
import sys
import urllib.request

connection = sqlite3.connect(sys.argv[1])
sources = {r[0] for r in connection.execute('SELECT DISTINCT source FROM device_evidence')}
assert {'mdns', 'ssdp', 'dhcp6'} <= sources, sorted(sources)
lengths = {}
for source in ['mdns', 'ssdp']:
    attributes = [json.loads(r[0])['attributes'] for r in connection.execute(
        "SELECT metadata_json FROM device_evidence WHERE source=? AND field='observation'", (source,))]
    complete = [int(a['captured_length']) for a in attributes
                if a.get('truncated') == 'false' and a['captured_length'] == a['original_length']]
    expected = {'mdns': 770, 'ssdp': 830}[source]
    assert expected in complete, (source, complete)
    lengths[source] = max(complete)
dhcp6 = [json.loads(r[0])['attributes'] for r in connection.execute(
    "SELECT metadata_json FROM device_evidence WHERE source='dhcp6' AND field='observation'")]
assert any({'duid', 'vendor_specific', 'client_fqdn'} <= a.keys() for a in dhcp6), dhcp6
flows = {}
for protocol, port in [('tls', 18443), ('http', 18080)]:
    with urllib.request.urlopen(
            f'http://127.0.0.1:28091/internal/flows?from=0&to=9223372036854775807&limit=100&port={port}') as response:
        rows = json.load(response)['data']
    assert any(r['protocol_id'] == protocol and r['application'] == 'youtube'
               and r['category'] == 'streaming' and r['domain'] == 'www.youtube.com' for r in rows), rows
    flows[protocol] = rows
assert connection.execute("SELECT count(*) FROM devices WHERE device_type='printer'").fetchone()[0] > 0
with urllib.request.urlopen('http://127.0.0.1:28091/internal/settings/diagnostics') as response:
    diagnostics = json.load(response)['data']
assert diagnostics['sampling']['packet_count'] > 0
print(json.dumps({'result': 'OPENWRT_RECOGNITION_E2E_OK', 'complete_discovery_lengths': lengths,
                  'evidence_sources': sorted(sources), 'flows': flows,
                  'sampling_packets': diagnostics['sampling']['packet_count']}, indent=2))
