#!/usr/bin/env python3
"""Deploy a renewed CA certificate using immutable pairs and a recoverable config switch.

Policy is a root-owned private JSON file. No credentials or parser errors are logged.
The existing mygotunnelctl server lock excludes binary upgrade transactions.
"""
import argparse
import base64
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import re
import socket
import ssl
import stat
import subprocess
import tempfile
import time


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('unsafe certificate state directory')


def atomic_bytes(path, data, ops):
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        ops.fsync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_regular(path, limit=1024*1024, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > limit:
            raise RuntimeError('unsafe certificate input')
        if private and info.st_mode & 0o077:
            raise RuntimeError('private input permissions are too broad')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit+1)
        if len(data) > limit:
            raise RuntimeError('certificate input too large')
        return data
    finally:
        os.close(fd)


def validate_pair(cert, key, domain):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key), password=lambda: '')
    subprocess.run(['openssl', 'verify', '-CApath', '/etc/ssl/certs', '-untrusted', str(cert),
                    '-verify_hostname', domain, str(cert)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    subprocess.run(['openssl', 'x509', '-in', str(cert), '-checkend', '86400', '-noout'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)


def probe_live(config, domain, verify_ca=True):
    cert_path = pathlib.Path(config['cert_file'])
    first = re.search(br'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', cert_path.read_bytes(), re.S)
    if first is None:
        raise RuntimeError('certificate missing')
    expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(first[0].decode('ascii'))).digest()
    host, port = config.get('listen_addr', ':9001').rsplit(':', 1)
    host = host.strip('[]')
    if host in ('', '0.0.0.0', '::'):
        host = '127.0.0.1'
    context = ssl.create_default_context()
    if not verify_ca:
        # Recovery may restore a formerly pinned self-signed certificate.
        # Its exact leaf digest is still checked against the private snapshot.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, int(port)), timeout=6) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as connection:
            if hashlib.sha256(connection.getpeercert(binary_form=True)).digest() != expected:
                raise RuntimeError('service did not load the expected certificate')


def activation_mode(binary, ops):
    try:
        capabilities = json.loads(ops.run(str(binary), '-capabilities'))
        if capabilities.get('certificate_reload') == 'sighup':
            return 'reload'
    except (subprocess.SubprocessError, ValueError, TypeError, AttributeError):
        pass
    return 'restart'


def activate(record, policy, ops, verify_ca=True):
    binary, config = pathlib.Path(policy['binary']), pathlib.Path(policy['config'])
    unit = policy['unit']
    expected_config = record['after_sha256'] if verify_ca else record['before_sha256']
    if ops.digest(config) != expected_config or ops.digest(binary) != record['binary_sha256'] or ops.unit_digest(unit) != record['unit_sha256']:
        raise RuntimeError('protected files changed before certificate activation')
    if record.get('activation', 'restart') == 'reload':
        pid = ops.run('systemctl', 'show', '-p', 'MainPID', '--value', unit)
        if not pid.isdecimal() or int(pid) == 0 or ops.digest(pathlib.Path('/proc')/pid/'exe') != record['binary_sha256']:
            raise RuntimeError('reload process identity mismatch')
        ops.run('systemctl', 'kill', '--kill-who=main', '--signal=HUP', unit)
        # Signal delivery is asynchronous. Verify the actual served certificate,
        # not merely signal acceptance or the config already on disk.
        deadline = time.monotonic()+10
        while True:
            try:
                probe_live(json.loads(config.read_bytes()), policy['domain'], verify_ca=verify_ca)
                break
            except (OSError, RuntimeError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        if ops.run('systemctl', 'show', '-p', 'MainPID', '--value', unit) != pid:
            raise RuntimeError('process changed during certificate reload')
    else:
        ops.run('systemctl', 'restart', unit)
    ops.validate_running(binary, config, unit, record['binary_sha256'], expected_config, record['unit_sha256'])


def guard_record(record, policy, ops):
    config = pathlib.Path(policy['config'])
    binary = pathlib.Path(policy['binary'])
    unit = policy['unit']
    if record.get('schema') != 1 or record.get('phase') not in ('prepared', 'committed'):
        raise RuntimeError('invalid certificate transaction')
    if record.get('activation', 'restart') not in ('reload', 'restart'):
        raise RuntimeError('invalid certificate activation mode')
    if record.get('config') != str(config) or record.get('binary') != str(binary) or record.get('unit') != unit:
        raise RuntimeError('certificate transaction policy changed')
    if ops.digest(binary) != record['binary_sha256'] or ops.unit_digest(unit) != record['unit_sha256']:
        raise RuntimeError('binary or unit changed during certificate transaction')
    if ops.digest(config) not in (record['before_sha256'], record['after_sha256']):
        raise RuntimeError('configuration changed during certificate transaction')


def recover(record, policy, ops, journal):
    guard_record(record, policy, ops)
    config, binary = pathlib.Path(policy['config']), pathlib.Path(policy['binary'])
    before = base64.b64decode(record['before'], validate=True)
    if digest_bytes(before) != record['before_sha256']:
        raise RuntimeError('certificate rollback snapshot changed')
    if record['phase'] == 'committed':
        if ops.digest(config) != record['after_sha256']:
            raise RuntimeError('committed certificate configuration changed')
        ops.ensure_running(binary, config, policy['unit'], record['binary_sha256'], record['after_sha256'], record['unit_sha256'])
        probe_live(json.loads(config.read_bytes()), policy['domain'])
        atomic_bytes(journal.parent/'previous-config.json', before, ops)
    else:
        atomic_bytes(config, before, ops)
        activate(record, policy, ops, verify_ca=False)
    journal.unlink()
    ops.fsync_directory(journal.parent)


def synchronize(policy, ops, check_only=False):
    domain = policy['domain']
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', domain):
        raise RuntimeError('invalid certificate domain')
    root = pathlib.Path(policy['state_dir'])
    private_directory(root)
    config_path, binary = pathlib.Path(policy['config']), pathlib.Path(policy['binary'])
    unit = policy['unit']
    journal = root/'transaction.json'
    ops.ensure_release_directory()
    with (ops.ROOT/'server.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if ops.recovery_pending('server'):
            raise RuntimeError('binary recovery is pending')
        if journal.exists():
            if check_only:
                raise RuntimeError('certificate recovery is pending')
            recover(ops.read_record(journal), policy, ops, journal)
            return {'ok': True, 'action': 'recovered', 'recovery_only': True}
        raw = read_regular(config_path, 32768, private=True)
        current = json.loads(raw)
        with tempfile.TemporaryDirectory(prefix='.pair-', dir=root) as temporary:
            stage = pathlib.Path(temporary)
            cert, key = stage/'fullchain.pem', stage/'key.pem'
            atomic_bytes(cert, read_regular(pathlib.Path(policy['source_cert'])), ops)
            atomic_bytes(key, read_regular(pathlib.Path(policy['source_key']), private=True), ops)
            validate_pair(cert, key, domain)
            if check_only:
                return {'ok': True, 'action': 'validated'}
            identity = ops.digest(cert)
            pair = root/identity
            if pair.exists():
                private_directory(pair)
                if ops.digest(pair/'fullchain.pem') != identity:
                    raise RuntimeError('stored certificate snapshot changed')
                validate_pair(pair/'fullchain.pem', pair/'key.pem', domain)
            else:
                ops.fsync_directory(stage)
                os.rename(stage, pair)
                ops.fsync_directory(root)
        next_config = dict(current, cert_file=str(pair/'fullchain.pem'), key_file=str(pair/'key.pem'))
        if current == next_config:
            # Avoid unnecessary restarts; detect a stale running certificate instead.
            probe_live(current, domain)
            return {'ok': True, 'action': 'unchanged'}
        after = (json.dumps(next_config, indent=2)+'\n').encode()
        pending = root/'candidate-config.json'
        atomic_bytes(pending, after, ops)
        try:
            ops.check(binary, pending)
        finally:
            pending.unlink()
        record = {'schema': 1, 'phase': 'prepared', 'config': str(config_path), 'binary': str(binary), 'unit': unit,
                  'activation': activation_mode(binary, ops),
                  'binary_sha256': ops.digest(binary), 'unit_sha256': ops.unit_digest(unit),
                  'before': base64.b64encode(raw).decode('ascii'), 'before_sha256': digest_bytes(raw), 'after_sha256': digest_bytes(after)}
        if config_path.read_bytes() != raw:
            raise RuntimeError('configuration changed before certificate deployment')
        ops.write_json(journal, record)
        try:
            if config_path.read_bytes() != raw:
                raise RuntimeError('configuration changed after preparing certificate deployment')
            atomic_bytes(config_path, after, ops)
            activate(record, policy, ops)
            probe_live(next_config, domain)
            record['phase'] = 'committed'
            ops.write_json(journal, record)
        except BaseException:
            # A failed commit fsync may still have published the committed record.
            record['phase'] = 'prepared'
            ops.write_json(journal, record)
            recover(record, policy, ops, journal)
            raise
        atomic_bytes(root/'previous-config.json', raw, ops)
        journal.unlink()
        ops.fsync_directory(root)
        return {'ok': True, 'action': 'updated', 'activation': record['activation']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=pathlib.Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('certificate deployment requires root')
    policy = json.loads(read_regular(args.policy, 32768, private=True))
    loader = importlib.machinery.SourceFileLoader('mygotunnelctl', '/usr/local/sbin/mygotunnelctl')
    spec = importlib.util.spec_from_loader(loader.name, loader)
    ops = importlib.util.module_from_spec(spec)
    loader.exec_module(ops)
    print(json.dumps(synchronize(policy, ops, args.check)))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error_type': type(error).__name__}))
        raise SystemExit(1)
