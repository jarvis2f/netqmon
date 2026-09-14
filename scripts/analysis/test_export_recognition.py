import contextlib
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from export_recognition import export


class ExportRecognitionTest(unittest.TestCase):
    def test_projection_is_read_only_and_excludes_sensitive_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / 'input.db'
            output = Path(temporary) / 'projection.json'
            connection = sqlite3.connect(database)
            connection.executescript('''
                CREATE TABLE devices(id,gateway_id,mac,hostname,vendor,device_type,os_family,model,private_mac,last_seen);
                CREATE TABLE device_evidence(gateway_id,mac,source,field,value,confidence,first_seen,last_seen,hit_count,metadata_json);
                CREATE TABLE flow_sessions(device_id,domain,remote_ip,remote_port,protocol,application_id,protocol_id,category_id,classification_evidence_json,upload_bytes,download_bytes,started_at,last_seen_at);
                CREATE TABLE dns_observations(domain);
                CREATE TABLE auth_secrets(secret);
                INSERT INTO auth_secrets VALUES ('excluded-auth-test-secret');
            ''')
            now = int(time.time() * 1000)
            mac = bytes([2, 0, 0, 0, 0, 2])
            connection.execute('INSERT INTO devices VALUES (?,?,?,?,?,?,?,?,?,?)',
                               (1, 'test', mac, 'test-printer', None, None, None, None, 1, now))
            connection.execute('INSERT INTO device_evidence VALUES (?,?,?,?,?,?,?,?,?,?)',
                               ('test', mac, 'ssdp', 'observation', 'ssdp', 1, now, now, 20,
                                json.dumps({'attributes': {'usn': 'uuid:netqmon-recognition',
                                                           'server': 'test-printer',
                                                           'pw': 'excluded-txt-test-secret'}})))
            connection.execute('INSERT INTO flow_sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                               (1, 'example.test', bytes([192, 0, 2, 1]), 443, 6, None, 'tls', None, '[]', 10, 20, now, now))
            connection.commit()
            connection.close()
            digest = hashlib.sha256(database.read_bytes()).digest()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                export(database, output)
            self.assertEqual(digest, hashlib.sha256(database.read_bytes()).digest())
            text = output.read_text()
            self.assertNotIn('excluded-auth-test-secret', text + stdout.getvalue())
            self.assertNotIn('excluded-txt-test-secret', text + stdout.getvalue())
            projection = json.loads(text)
            self.assertEqual(projection['fixture_ids'], [1])
            self.assertEqual(projection['flows'][0]['n'], 1)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with contextlib.redirect_stdout(stdout), self.assertRaises(FileExistsError):
                export(database, output)


if __name__ == '__main__':
    unittest.main()
