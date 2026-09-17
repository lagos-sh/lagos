"""Exercise the distributed executable without Rust or third-party Python modules."""
import argparse
import http.client
import http.server
import json
import pathlib
import re
import socket
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'native-lagos-ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def smoke(binary, schema_release):
    version = re.search(r'^version = "([^"]+)"', (ROOT / 'Cargo.toml').read_text(), re.M).group(1)
    assert subprocess.check_output([str(binary), '--version'], text=True).strip() == f'lagos {version}'
    for args, name in [(['schema'], 'gateway'), (['schema', '--routes'], 'routes')]:
        actual = subprocess.check_output([str(binary), *args])
        assert actual == (ROOT / 'schemas' / f'{name}.schema.json').read_bytes(), name
    with tempfile.TemporaryDirectory(prefix='lagos-native-') as directory:
        work = pathlib.Path(directory)
        subprocess.run([str(binary), 'init'], cwd=work, check=True, capture_output=True)
        comment = (work / 'gateway.yml').read_text().splitlines()[0]
        if schema_release:
            assert schema_release == version
            assert f'/v{version}/schemas/gateway.schema.json' in comment
        else:
            assert 'yaml-language-server' not in comment
        subprocess.run([str(binary), 'validate'], cwd=work, check=True, capture_output=True)
        subprocess.run([str(binary), 'init', '--docker', '--force'], cwd=work, check=True, capture_output=True)
        assert (work / 'Dockerfile').is_file()
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        config = {
            'server': {'listen': f'127.0.0.1:{port}', 'threads': 1},
            'defaults': {'methods': ['GET']},
            'upstreams': {'origin': f'http://127.0.0.1:{server.server_port}'},
            'routes': {'public': [{'prefix': '/native', 'upstream': 'origin'}]},
        }
        (work / 'gateway.yml').write_text(json.dumps(config))
        with (work / 'gateway.log').open('w') as log:
            proc = subprocess.Popen([str(binary), 'run'], cwd=work, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if proc.poll() is not None:
                        raise AssertionError((work / 'gateway.log').read_text())
                    try:
                        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
                        try:
                            conn.request('GET', '/native')
                            response = conn.getresponse()
                            assert response.status == 200 and response.read() == b'native-lagos-ok'
                        finally:
                            conn.close()
                        break
                    except (OSError, http.client.HTTPException):
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
    print('Native version, schemas, init, validation, and proxy smoke checks passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--schema-release', default='')
    args = parser.parse_args()
    smoke(args.binary.resolve(strict=True), args.schema_release)
