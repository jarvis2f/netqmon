#!/usr/bin/env python3
"""Real Linux bridge/TC capture -> Agent -> native nDPI -> SQLite assertions.

Run as root in a disposable privileged Linux container with the repository at cwd.
Only constructed test traffic is transmitted; packet payloads are never saved or printed.
"""
import json
import os
import pathlib
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time


def name(value):
    return b''.join(bytes([len(p)]) + p.encode() for p in value.split('.')) + b'\0'


def mdns():
    instance = 'Netqmon HP LaserJet._ipp._tcp.local'
    service = '_ipp._tcp.local'
    def rr(owner, kind, data):
        return name(owner) + struct.pack('!HHIH', kind, 1, 120, len(data)) + data
    txt = [b'model=HP LaserJet', b'netqmon-test=' + b'x' * 225,
           b'pad1=' + b'y' * 225, b'pad2=' + b'z' * 225]
    records = [rr(service, 12, name(instance)),
               rr(instance, 33, struct.pack('!HHH', 0, 0, 631) + name('HP-LaserJet.local')),
               rr(instance, 16, b''.join(bytes([len(t)]) + t for t in txt))]
    packet = struct.pack('!HHHHHH', 0, 0x8400, 0, 3, 0, 0) + b''.join(records)
    assert 576 < len(packet) < 1400
    return packet


def emit(interface, ipv4='192.0.2.2', ipv6='fd42:6e71::2', dhcp6_destination='ff02::1:2'):
    def udp4(port, destination, data):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ipv4))
            sock.bind((ipv4, port))
            sock.sendto(data, (destination, port if port != 68 else 67))
    udp4(5353, '224.0.0.251', mdns())
    ssdp = (b'NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
            b'NT: urn:schemas-upnp-org:device:Printer:1\r\nNTS: ssdp:alive\r\n'
            b'SERVER: HP LaserJet UPnP/1.1\r\nUSN: uuid:netqmon-recognition\r\n'
            b'X-Netqmon-Test: ' + b'x' * 650 + b'\r\n\r\n')
    udp4(1900, '239.255.255.250', ssdp)
    mac = bytes.fromhex(pathlib.Path('/sys/class/net/' + interface + '/address').read_text().strip().replace(':', ''))
    dhcp = bytearray(240)
    dhcp[:4] = bytes([1, 1, 6, 0])
    dhcp[4:8] = b'NQMT'
    dhcp[12:16] = socket.inet_aton(ipv4)
    dhcp[28:34] = mac
    dhcp[236:240] = b'\x63\x82\x53\x63'
    def option(code, data): return bytes([code, len(data)]) + data
    dhcp += option(53, b'\x03') + option(12, b'HP-LaserJet') + option(60, b'HP LaserJet') + option(61, b'\x01' + mac) + b'\xff'
    udp4(68, '255.255.255.255', dhcp)
    def option6(code, data): return struct.pack('!HH', code, len(data)) + data
    dhcp6 = b'\x01NQM' + option6(1, b'\x00\x03\x00\x01' + mac)
    dhcp6 += option6(16, struct.pack('!IH', 424242, 11) + b'HP LaserJet')
    dhcp6 += option6(17, struct.pack('!IHH', 424242, 1, 11) + b'HP LaserJet')
    dhcp6 += option6(39, b'\x00' + name('HP-LaserJet.local'))
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        index = socket.if_nametoindex(interface)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        sock.bind((ipv6, 546, 0, index))
        sock.sendto(dhcp6, (dhcp6_destination, 547, 0, index))
    return {'mdns_length': len(mdns()), 'ssdp_length': len(ssdp), 'sources_sent': ['mdns','ssdp','dhcp','dhcp6']}


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--emit':
        print(json.dumps(emit(*sys.argv[2:])))
        return
    if os.geteuid() != 0: raise SystemExit('requires root in a disposable Linux container')
    root = pathlib.Path.cwd()
    work = pathlib.Path(tempfile.mkdtemp(prefix='netqmon-recognition-'))
    processes = []
    def run(args, **kwargs): return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)
    def spawn(args, filename, env=None):
        log = (work / filename).open('w')
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=env)
        log.close()
        processes.append(process)
        return process
    if pathlib.Path('/sys/class/net/br-lan').exists(): raise SystemExit('refusing to alter existing br-lan')
    if pathlib.Path('/etc/netqmon/credentials.toml').exists(): raise SystemExit('refusing to replace existing Agent credentials')
    try:
        run(['ip','link','add','br-lan','type','bridge'])
        run(['ip','addr','add','192.0.2.1/24','dev','br-lan'])
        run(['ip','-6','addr','add','fd42:6e71::1/64','dev','br-lan','nodad'])
        run(['ip','link','set','br-lan','up'])
        run(['ip','link','add','nqm-port','type','veth','peer','name','nqm-peer'])
        run(['ip','link','set','nqm-port','master','br-lan'])
        run(['ip','link','set','nqm-port','up'])
        run(['ip','netns','add','nqm-client'])
        run(['ip','link','set','nqm-peer','netns','nqm-client'])
        ns = ['ip','netns','exec','nqm-client']
        for cmd in [['link','set','lo','up'],['link','set','nqm-peer','up'],['addr','add','192.0.2.2/24','dev','nqm-peer'],['-6','addr','add','fd42:6e71::2/64','dev','nqm-peer','nodad'],['route','add','default','via','192.0.2.1']]:
            run(ns+['ip']+cmd)
        run(['ip','addr','add','198.51.100.1/32','dev','lo'])
        env = dict(os.environ, NETQMON_COLLECTOR_PUBLIC_ADDR='0.0.0.0:18090', NETQMON_COLLECTOR_INTERNAL_ADDR='127.0.0.1:18091', NETQMON_COLLECTOR_ENROLLMENT_TOKEN='recognition-test', NETQMON_COLLECTOR_DATABASE_PATH=str(work/'test.db'), NETQMON_COLLECTOR_GEO_DIR=str(work/'geo'), NETQMON_DPI_ENABLED='true')
        collector = spawn([str(root/'target/debug/netqmon-collector')], 'collector.log', env)
        import urllib.request
        for _ in range(100):
            if collector.poll() is not None: raise RuntimeError('Collector exited; see '+str(work/'collector.log'))
            try:
                urllib.request.urlopen('http://127.0.0.1:18090/health',timeout=1).close()
                break
            except OSError: time.sleep(.1)
        env = dict(os.environ, NETQMON_CONTROLLER_URL='http://127.0.0.1:18090', NETQMON_TOKEN='recognition-test', NETQMON_LOG_LEVEL='debug', NETQMON_BATCH_INTERVAL_MS='1000', NETQMON_POLL_INTERVAL_MS='100', NETQMON_SAMPLE_ENABLED='true', NETQMON_TCP_IDLE_TIMEOUT_SECONDS='2')
        agent = spawn([str(root/'target/debug/netqmon-agent'),'--interface','br-lan'], 'agent.log',env)
        for _ in range(100):
            if agent.poll() is not None: raise RuntimeError('Agent exited; see '+str(work/'agent.log'))
            attach_log = (work/'agent.log').read_text()
            if ('attached tcx ingress and egress hooks' in attach_log or
                    'attached netlink ingress and egress hooks' in attach_log):
                break
            time.sleep(.1)
        for direction in ['ingress','egress']:
            output=run(['tc','filter','show','dev','br-lan',direction]).stdout
            assert 'bpf' in output, direction
        time.sleep(2)
        sent = run(ns+['python3',str(pathlib.Path(__file__).resolve()),'--emit','nqm-peer']).stdout
        run(['openssl','req','-x509','-newkey','rsa:2048','-keyout',str(work/'key.pem'),'-out',str(work/'cert.pem'),'-days','1','-nodes','-subj','/CN=www.youtube.com'])
        spawn(['openssl','s_server','-accept','198.51.100.1:18443','-cert',str(work/'cert.pem'),'-key',str(work/'key.pem'),'-www'],'tls-server.log')
        spawn(['python3','-m','http.server','18080','--bind','198.51.100.1','--directory',str(work)],'http-server.log')
        time.sleep(.5)
        run(ns+['curl','--noproxy','*','-kfsS','--max-time','10','--resolve','www.youtube.com:18443:198.51.100.1','https://www.youtube.com:18443/','-o','/dev/null'])
        run(ns+['curl','--noproxy','*','-fsS','--max-time','10','-H','Host: www.youtube.com','http://198.51.100.1:18080/','-o','/dev/null'])
        time.sleep(5)
        with urllib.request.urlopen('http://127.0.0.1:18091/internal/settings/diagnostics') as response: diagnostics=json.load(response)['data']
        con=sqlite3.connect(work/'test.db')
        sources={row[0] for row in con.execute('SELECT DISTINCT source FROM device_evidence')}
        assert {'mdns','ssdp','dhcp','dhcp6'} <= sources, sorted(sources)
        agent_log = (work/'agent.log').read_text()
        assert 'client_id_len=7' in agent_log, 'DHCP option 61 did not reach Agent'
        assert 'vendor_class=HP LaserJet' in agent_log, 'DHCP vendor class was lost'

        metadata=[json.loads(row[0]) for row in con.execute("SELECT metadata_json FROM device_evidence WHERE source='mdns' AND field='observation'")]
        assert any(int(m['attributes']['captured_length'])>576 and m['attributes']['truncated']=='false' for m in metadata)
        tls=con.execute("SELECT protocol_id,application_id,category_id,domain FROM flow_sessions WHERE remote_port=18443").fetchall()
        assert any(row[:3]==('tls','youtube','streaming') and row[3]=='www.youtube.com' for row in tls),tls
        http=con.execute("SELECT protocol_id,application_id,category_id,domain FROM flow_sessions WHERE remote_port=18080").fetchall()
        assert any(row[:3]==('http','youtube','streaming') for row in http),http
        assert con.execute('SELECT count(*) FROM dns_observations').fetchone()[0]==0
        assert diagnostics['sampling']['packet_count']>0
        assert diagnostics['recognition']['device']['evidence_source_coverage']['mdns']>0
        print(json.dumps({'result':'LINUX_RECOGNITION_E2E_OK','traffic_generation':json.loads(sent),'evidence_sources':sorted(sources),'tls':tls,'http':http,'sampling_packets':diagnostics['sampling']['packet_count'],'artifact_directory':str(work)},indent=2))
    finally:
        for process in reversed(processes):
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill();process.wait()
        pathlib.Path('/etc/netqmon/credentials.toml').unlink(missing_ok=True)
        for cmd in [['ip','netns','del','nqm-client'],['ip','link','del','nqm-port'],['ip','link','del','br-lan'],['ip','addr','del','198.51.100.1/32','dev','lo']]:
            subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__': main()
