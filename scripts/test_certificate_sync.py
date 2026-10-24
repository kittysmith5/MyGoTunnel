import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock


def load(name):
    spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CertificateSyncTest(unittest.TestCase):
    def setUp(self):
        self.module = load('sync_certificate')
        self.ops = load('mygotunnelctl')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.ops.ROOT = self.root/'releases'
        self.ops.ROOT.mkdir(mode=0o700)
        self.config = self.root/'server.json'
        self.original = {'auth_token': 'test-only-secret', 'listen_addr': ':8443', 'cert_file': 'old.pem', 'key_file': 'old.key', 'https_entry': {'enabled': True}}
        self.config.write_text(json.dumps(self.original)); self.config.chmod(0o600)
        self.binary = self.root/'server'; self.binary.write_bytes(b'test binary')
        self.cert = self.root/'source.pem'; self.cert.write_bytes(b'test certificate')
        self.key = self.root/'source.key'; self.key.write_bytes(b'test key'); self.key.chmod(0o600)
        self.policy = dict(domain='example.com', config=str(self.config), binary=str(self.binary), unit='mygotunnel-server.service',
                           source_cert=str(self.cert), source_key=str(self.key), state_dir=str(self.root/'certificates'))
        self.restart = mock.Mock()
        for obj, name, value in [(self.module, 'validate_pair', mock.Mock()), (self.module, 'probe_live', mock.Mock()),
                                 (self.module, 'activation_mode', mock.Mock(return_value='restart')),
                                 (self.ops, 'run', self.restart), (self.ops, 'validate_running', mock.Mock()),
                                 (self.ops, 'ensure_running', mock.Mock()), (self.ops, 'unit_digest', lambda unit: 'unit-hash'),
                                 (self.ops, 'check', mock.Mock())]:
            patch = mock.patch.object(obj, name, value); patch.start(); self.addCleanup(patch.stop)
        # Production enforces UID 0. Allow private test files for non-root test runners.
        self.uid = mock.patch.object(self.module.os, 'geteuid', return_value=0)
        self.uid.start(); self.addCleanup(self.uid.stop)
        if os.getuid() != 0:
            self.skipTest('root-owned certificate snapshots require root')

    def sync(self, **kwargs):
        return self.module.synchronize(self.policy, self.ops, **kwargs)

    def test_snapshot_and_idempotent_deployment_preserve_credentials(self):
        self.assertEqual(self.sync()['action'], 'updated')
        after = json.loads(self.config.read_bytes())
        for k in self.original:
            if k not in ('cert_file', 'key_file'): self.assertEqual(after[k], self.original[k])
        self.assertEqual(pathlib.Path(after['cert_file']).read_bytes(), b'test certificate')
        self.assertEqual(pathlib.Path(after['key_file']).stat().st_mode & 0o777, 0o600)
        self.cert.write_bytes(b'renewed certificate')
        self.assertEqual(pathlib.Path(after['cert_file']).read_bytes(), b'test certificate')
        self.cert.write_bytes(b'test certificate')
        self.assertEqual(self.sync()['action'], 'unchanged')
        self.assertEqual(self.restart.call_count, 1)

    def test_invalid_pair_and_preflight_failure_do_not_change_service(self):
        before = self.config.read_bytes()
        self.module.validate_pair.side_effect = RuntimeError('invalid pair')
        with self.assertRaises(RuntimeError): self.sync()
        self.assertEqual(self.config.read_bytes(), before); self.restart.assert_not_called()
        self.module.validate_pair.side_effect = None
        self.ops.check.side_effect = RuntimeError('invalid config')
        with self.assertRaises(RuntimeError): self.sync()
        self.assertEqual(self.config.read_bytes(), before); self.restart.assert_not_called()

    def test_live_probe_failure_rolls_back_config_and_restarts_previous(self):
        before = self.config.read_bytes()
        self.module.probe_live.side_effect = RuntimeError('wrong certificate')
        with self.assertRaises(RuntimeError): self.sync()
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.restart.call_count, 2)
        self.assertFalse((self.root/'certificates/transaction.json').exists())

    def test_pending_binary_transaction_blocks_certificate_switch(self):
        self.ops.intent_path('server').write_text('{}')
        with self.assertRaises(RuntimeError): self.sync()
        self.restart.assert_not_called()

    def test_crash_after_config_write_recovers_previous_without_second_change(self):
        original_write = self.ops.write_json
        def crash_commit(path, value):
            if value.get('phase') == 'committed': raise SystemExit(9)
            original_write(path, value)
        # Simulate process death, bypassing Python's rollback exception handler.
        with mock.patch.object(self.ops, 'write_json', side_effect=crash_commit), mock.patch.object(self.module, 'recover', side_effect=SystemExit(9)):
            with self.assertRaises(SystemExit): self.sync()
        self.assertNotEqual(json.loads(self.config.read_bytes())['cert_file'], 'old.pem')
        self.assertTrue((self.root/'certificates/transaction.json').exists())
        result = self.sync()
        self.assertEqual(result['action'], 'recovered')
        self.assertEqual(json.loads(self.config.read_bytes()), self.original)

    def test_committed_cleanup_failure_does_not_downgrade(self):
        original_unlink = pathlib.Path.unlink
        def fail_unlink(path, *args, **kwargs):
            if path.name == 'transaction.json': raise OSError('cleanup failed')
            return original_unlink(path, *args, **kwargs)
        with mock.patch.object(pathlib.Path, 'unlink', fail_unlink):
            with self.assertRaises(OSError): self.sync()
        after = self.config.read_bytes()
        self.assertEqual(self.sync()['action'], 'recovered')
        self.assertEqual(self.config.read_bytes(), after)
        self.assertEqual(self.restart.call_count, 1)

    def test_external_config_change_keeps_recovery_pending(self):
        def change_external(*args, **kwargs):
            self.config.write_text(json.dumps(dict(self.original, auth_token='external-change')))
            raise RuntimeError('external config change')
        self.module.probe_live.side_effect = change_external
        with self.assertRaises(RuntimeError): self.sync()
        self.assertEqual(json.loads(self.config.read_bytes())['auth_token'], 'external-change')
        self.assertTrue((self.root/'certificates/transaction.json').exists())

    def test_check_only_and_unsafe_key(self):
        self.assertEqual(self.sync(check_only=True)['action'], 'validated')
        self.restart.assert_not_called()
        self.assertEqual(json.loads(self.config.read_bytes()), self.original)
        self.key.chmod(0o644)
        with self.assertRaises(RuntimeError): self.sync()
        self.key.chmod(0o600)
        self.key.unlink(); self.key.symlink_to(self.cert)
        with self.assertRaises(OSError): self.sync()

    def enable_reload(self):
        self.module.activation_mode.return_value = 'reload'
        self.restart.return_value = '1234'
        original_digest = self.ops.digest
        patch = mock.patch.object(self.ops, 'digest', side_effect=lambda path: original_digest(self.binary) if str(path) == '/proc/1234/exe' else original_digest(path))
        patch.start(); self.addCleanup(patch.stop)

    def test_hot_reload_keeps_pid_and_does_not_restart(self):
        self.enable_reload()
        result = self.sync()
        self.assertEqual(result['activation'], 'reload')
        self.assertIn(mock.call('systemctl', 'kill', '--kill-who=main', '--signal=HUP', self.policy['unit']), self.restart.call_args_list)
        self.assertNotIn(mock.call('systemctl', 'restart', self.policy['unit']), self.restart.call_args_list)
        self.assertEqual(self.sync()['action'], 'unchanged')

    def test_hot_reload_waits_for_new_leaf_and_rolls_back_without_restart(self):
        self.enable_reload()
        before = self.config.read_bytes()
        # The first signal never loads the new pair; rollback reload succeeds.
        self.module.probe_live.side_effect = [RuntimeError('stale leaf'), None]
        with mock.patch.object(self.module.time, 'monotonic', side_effect=[0, 11, 12]):
            with self.assertRaises(RuntimeError): self.sync()
        self.assertEqual(self.config.read_bytes(), before)
        signals = [call for call in self.restart.call_args_list if 'kill' in call.args]
        self.assertEqual(len(signals), 2)
        self.assertNotIn(mock.call('systemctl', 'restart', self.policy['unit']), self.restart.call_args_list)
        self.assertFalse((self.root/'certificates/transaction.json').exists())

    def test_hot_reload_rejects_running_binary_mismatch(self):
        self.module.activation_mode.return_value = 'reload'
        self.restart.return_value = '0'
        before = self.config.read_bytes()
        with self.assertRaises(RuntimeError): self.sync()
        self.assertEqual(self.config.read_bytes(), before)
        self.assertTrue((self.root/'certificates/transaction.json').exists())
        self.assertFalse(any('kill' in call.args for call in self.restart.call_args_list))


class CapabilitiesTest(unittest.TestCase):
    def test_capability_detection_preserves_legacy_restart(self):
        module, ops = load('sync_certificate'), mock.Mock()
        for output, expected in [('{}', 'restart'), ('not json', 'restart'), ('{"certificate_reload":"sighup"}', 'reload'), ('{"certificate_reload":"unsupported"}', 'restart')]:
            ops.run.return_value = output
            self.assertEqual(module.activation_mode(pathlib.Path('/test/server'), ops), expected)


if __name__ == '__main__':
    unittest.main()
