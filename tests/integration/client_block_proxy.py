#!/usr/bin/env python3
"""Root-only isolated nft client-block regression test using the Agent test binary.

Usage: python3 tests/integration/client_block_proxy.py /absolute/path/to/netqmon_agent-test
All interfaces, routes, sysctls and firewall rules live in temporary namespaces.
"""
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time


def server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            try:
                if self.path == '/stream':
                    for _ in range(300):
                        self.wfile.write(b'x' * 1024)
                        self.wfile.flush()
                        time.sleep(0.05)
                else:
                    self.wfile.write(b'ok\n')
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_):
            pass

    class V6(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

    servers = []
    for port in (8080, 18080):
        servers.extend([http.server.ThreadingHTTPServer(('0.0.0.0', port), Handler), V6(('::', port), Handler)])
    for httpd in servers:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    threading.Event().wait()


def main(binary):
    if os.geteuid() != 0:
        raise SystemExit('requires root on an isolated Linux test host')
    binary = os.path.abspath(binary)
    script = os.path.abspath(__file__)
    prefix = 'nqmp-' + str(os.getpid())
    client, router, internet = [prefix + suffix for suffix in ('-c', '-r', '-s')]
    namespaces, processes = [], []

    def run(*args, ns=None, input=None, check=True):
        cmd = (['ip', 'netns', 'exec', ns] if ns else []) + list(args)
        result = subprocess.run(cmd, input=input, text=True, capture_output=True, timeout=30)
        if check and result.returncode:
            raise RuntimeError(f'{cmd}: {result.stderr}\n{result.stdout}')
        return result

    def ip(ns, *args):
        return run('ip', *args, ns=ns)

    def http(host, port, allowed, label):
        address = '[' + host + ']' if ':' in host else host
        result = run('curl', '--noproxy', '*', '-g', '-sS', '--connect-timeout', '1', '--max-time', '2',
                     '-o', '/dev/null', '-w', '%{http_code}', f'http://{address}:{port}/', ns=client, check=False)
        if allowed:
            assert result.returncode == 0 and result.stdout == '200', (label, result)
        else:
            assert result.returncode == 28 and result.stdout == '000', (label, result)
        print('PASS:', label, flush=True)

    def policy(action):
        env = {
            'NETQMON_POLICY_NETNS_ACTION': action,
            'NETQMON_POLICY_NETNS_NEIGHBORS': json.dumps([
                ['02:00:00:00:01:02', '192.0.2.2'], ['02:00:00:00:01:02', 'fd42:1::2']]),
            'NETQMON_POLICY_NETNS_BLOCK_MAC': '02:00:00:00:01:02',
            'NETQMON_POLICY_NETNS_LAN': 'r-lan', 'NETQMON_POLICY_NETNS_WAN': 'r-wan',
            'NETQMON_POLICY_NETNS_INTERNAL_V4': '192.0.2.0/24',
            'NETQMON_POLICY_NETNS_INTERNAL_V6': 'fd42:1::/64',
        }
        result = run('env', *[k + '=' + v for k, v in env.items()], binary,
                     'policy::nft::tests::applies_agent_owned_policy_from_test_namespace_neighbors',
                     '--exact', '--ignored', '--nocapture', ns=router)
        assert '1 passed' in result.stdout, result

    try:
        for ns in (client, router, internet):
            run('ip', 'netns', 'add', ns)
            namespaces.append(ns)
            ip(ns, 'link', 'set', 'lo', 'up')
            run('sysctl', '-qw', 'net.ipv6.conf.default.accept_dad=0', 'net.ipv6.conf.all.accept_dad=0', ns=ns)
        for left_ns, left, right_ns, right in ((client, 'c-lan', router, 'r-lan'), (router, 'r-wan', internet, 's-wan')):
            ip(left_ns, 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
            ip(left_ns, 'link', 'set', right, 'netns', right_ns)
        for ns, dev, v4, v6 in ((client, 'c-lan', '192.0.2.2/24', 'fd42:1::2/64'),
                               (router, 'r-lan', '192.0.2.1/24', 'fd42:1::1/64'),
                               (router, 'r-wan', '198.51.100.1/24', '2001:db8:2::1/64'),
                               (internet, 's-wan', '198.51.100.2/24', '2001:db8:2::2/64')):
            ip(ns, 'addr', 'add', v4, 'dev', dev)
            ip(ns, '-6', 'addr', 'add', v6, 'dev', dev, 'nodad')
            ip(ns, 'link', 'set', dev, 'up')
        ip(client, 'link', 'set', 'c-lan', 'address', '02:00:00:00:01:02')
        for ns, v4, v6 in ((client, '192.0.2.1', 'fd42:1::1'), (internet, '198.51.100.1', '2001:db8:2::1')):
            ip(ns, 'route', 'add', 'default', 'via', v4)
            ip(ns, '-6', 'route', 'add', 'default', 'via', v6)
        ip(router, 'addr', 'add', '203.0.113.1/32', 'dev', 'lo')
        ip(router, '-6', 'addr', 'add', '2001:db8:ffff::1/128', 'dev', 'lo', 'nodad')
        run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1', ns=router)
        run('nft', '-f', '-', ns=router, input='''table inet test_proxy {
 chain proxy_redirect {
  type nat hook prerouting priority -100; policy accept;
  iifname "r-lan" tcp dport 8081 redirect to :18080
 }
}
''')
        for ns in (router, internet):
            processes.append(subprocess.Popen(['ip', 'netns', 'exec', ns, sys.executable, script, '--server']))
        time.sleep(0.4)
        for host in ('198.51.100.2', '2001:db8:2::2'):
            http(host, 8080, True, 'baseline direct ' + host)
            http(host, 8081, True, 'baseline proxy ' + host)
        # Keep a download open so the post-NAT guard must block locally
        # generated proxy replies, independently of dropping new connections.
        stream = subprocess.Popen(['ip', 'netns', 'exec', client, 'curl', '--noproxy', '*', '-sS',
                                   '--max-time', '10', 'http://198.51.100.2:8081/stream'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(stream)
        time.sleep(0.3)
        policy('replace')
        time.sleep(0.3)
        rules = json.loads(run('nft', '-j', 'list', 'table', 'inet', 'netqmon_policy', ns=router).stdout)
        counters = [expr['counter']['packets'] for item in rules['nftables'] if 'rule' in item
                    and item['rule'].get('comment') == 'netqmon post-proxy client Internet block'
                    for expr in item['rule']['expr'] if 'counter' in expr]
        assert sum(counters) > 0, 'existing transparent-proxy download bypassed the post-NAT guard'
        print('PASS: established proxy download blocked after reverse NAT', flush=True)
        for host in ('198.51.100.2', '2001:db8:2::2'):
            http(host, 8080, False, 'blocked direct ' + host)
            http(host, 8081, False, 'blocked proxy ' + host)
        ip(client, '-6', 'neigh', 'flush', 'dev', 'c-lan')
        for host in ('192.0.2.1', 'fd42:1::1', '203.0.113.1', '2001:db8:ffff::1'):
            http(host, 18080, True, 'preserved router service ' + host)
        policy('clear')
        for host in ('198.51.100.2', '2001:db8:2::2'):
            http(host, 8080, True, 'restored direct ' + host)
            http(host, 8081, True, 'restored proxy ' + host)
    except Exception:
        for ns in namespaces:
            print(ns, run('ip', '-6', 'addr', ns=ns, check=False).stdout, flush=True)
            print(run('ip', '-6', 'route', ns=ns, check=False).stdout, flush=True)
            print(run('ip', '-6', 'neigh', ns=ns, check=False).stdout, flush=True)
        raise
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for ns in reversed(namespaces):
            run('ip', 'netns', 'delete', ns, check=False)


if __name__ == '__main__':
    if sys.argv[1:] == ['--server']:
        server()
    elif len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        raise SystemExit(__doc__)
