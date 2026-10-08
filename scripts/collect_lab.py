"""Capture controlled requests locally in Nginx combined format, without exploiting a service.
This is an HTTP lab emitter, not a real Nginx/SSH daemon capture.
"""
import argparse
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

TARGETS = [('/health', 'benign'), ('/search?q=select+database+union', 'benign'),
           ('/search?q=1%27+OR+%271%27=%271', 'sqli_attempt'),
           ('/search?q=%3Cscript%3Ealert(1)%3C/script%3E', 'xss_attempt')]


def collect(directory):
    entries = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            timestamp = datetime.now(timezone.utc).strftime('%d/%b/%Y:%H:%M:%S +0000')
            # No shell, SQL engine or script interpreter receives request parameters.
            entries.append(f'{self.client_address[0]} - - [{timestamp}] "GET {self.path} HTTP/1.1" 200 2 "-" "controlled-lab"')
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for target, _ in TARGETS:
            with urlopen(f'http://127.0.0.1:{server.server_port}{target}', timeout=5) as response:
                assert response.read() == b'ok'
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    directory.mkdir(parents=True, exist_ok=True)
    (directory/'access.log').write_text('\n'.join(entries)+'\n')
    (directory/'labels.json').write_text(json.dumps({'source': 'scripts/collect_lab.py',
        'capture_kind': 'real loopback HTTP requests; Python server emits Nginx combined log format',
        'not_real_nginx': True, 'not_exploitation_ground_truth': True,
        'cases': [{'line': i+1, 'target': target, 'expected': label} for i,(target,label) in enumerate(TARGETS)]},indent=2)+'\n')
    print(f'Captured {len(entries)} controlled requests to {directory}')


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,default=Path('/tmp/copilot-lab'))
    collect(parser.parse_args().output)
