#!/usr/bin/env python3
"""Read-only SQLite projection for offline recognition replay (no auth/payload tables)."""
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import sys
import time


def export(database, output):
    connection = sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA query_only=ON')
    connection.execute('BEGIN')
    now = int(time.time() * 1000)
    devices = []
    for row in connection.execute('SELECT id,gateway_id,mac,hostname,vendor,device_type,os_family,model,private_mac,last_seen FROM devices'):
        device = dict(row)
        device['mac'] = list(device['mac'])
        devices.append(device)
    allowed = {'model', 'md', 'am', 'manufacturer', 'server', 'user-agent', 'st', 'nt',
               'message_kind', 'duid', 'oro', 'vendor_class', 'vendor_specific', 'client_fqdn',
               'vid', 'pid', 'vp', 'dt', 'ci', 'osxvers', 'captured_length', 'original_length',
               'truncated', 'c#', 's#', 'sf', 'ff', 'pv'}
    evidence = []
    fixture_keys = set()
    for row in connection.execute('SELECT gateway_id,mac,source,field,value,confidence,first_seen,last_seen,hit_count,metadata_json FROM device_evidence'):
        item = dict(row)
        item['mac'] = list(item['mac'])
        metadata = json.loads(item['metadata_json'])
        attributes = metadata.get('attributes', {})
        # Explicit marker emitted by this repository's disposable wire-path tests.
        if attributes.get('usn') == 'uuid:netqmon-recognition':
            fixture_keys.add((item['gateway_id'], tuple(item['mac'])))
        metadata['attributes'] = {k: v for k, v in attributes.items() if k in allowed}
        item['metadata_json'] = json.dumps(metadata)
        evidence.append(item)
    flows = []
    for row in connection.execute('''SELECT device_id,domain,remote_ip,remote_port,protocol,
        application_id,protocol_id,category_id,classification_evidence_json,count(*) n,
        sum(upload_bytes+download_bytes) bytes FROM flow_sessions
        WHERE last_seen_at>=? AND last_seen_at<=? GROUP BY 1,2,3,4,5,6,7,8,9''', (now - 86400000, now)):
        flow = dict(row)
        flow['remote_ip'] = str(ipaddress.ip_address(flow['remote_ip']))
        flows.append(flow)
    result = {'snapshot_at': now, 'since': now - 86400000, 'source': str(database.resolve()),
              'devices': devices, 'evidence': evidence, 'flows': flows,
              'fixture_ids': [d['id'] for d in devices if (d['gateway_id'], tuple(d['mac'])) in fixture_keys],
              'range': dict(connection.execute('SELECT min(started_at) first,max(last_seen_at) last,count(*) total FROM flow_sessions').fetchone()),
              'dns_count': connection.execute('SELECT count(*) FROM dns_observations').fetchone()[0]}
    connection.rollback()
    connection.close()
    # Exclusive creation prevents accidental overwrite of any input or existing artifact.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(result, stream)
    print(json.dumps({'clients': len(devices), 'flow_sessions': sum(f['n'] for f in flows),
                      'fixture_clients': len(result['fixture_ids']), 'snapshot_at': now}))


if __name__ == '__main__':
    export(Path(sys.argv[1]), Path(sys.argv[2]))
