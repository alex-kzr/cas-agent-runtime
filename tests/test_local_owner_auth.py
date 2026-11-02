import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.providers.claude.working_backend import DockerWorkingBackend
from agent_runtime.telemetry.recorder import atomic_json
from agent_runtime.tasks.working_sessions import WorkingSessions
from test_working_sessions import FakeBackend


class LocalOwnerTests(unittest.TestCase):
    def test_legacy_history_masks_newly_sensitive_fields_without_modifying_bytes(self):
        from test_working_sessions import report
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            backend = FakeBackend()
            store = WorkingSessions(root / 'data', backend=backend, root=root)
            sid = store.create('Synthetic')['session_id']
            store.add(sid, title='Task', prompt='Synthetic task')
            row = store.prepare(sid)
            original = store.load(sid)
            original['title'] = 'accessToken: SYNTHETIC_PRIVATE_TITLE'
            original['tasks'][0]['prompt'] = 'accessToken: SYNTHETIC_PRIVATE_PROMPT'
            original.update(status='COMPLETED', cleanup='CONFIRMED',
                            results=[report(original, 0, text='refreshToken: SYNTHETIC_PRIVATE_RESULT')])
            path = store.folder(sid) / 'session.json'
            atomic_json(path, original)
            before = path.read_bytes()
            detail = store.get(sid)
            history = store.list()
            self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps([detail, history]))
            self.assertEqual(detail['status'], 'COMPLETED')
            self.assertEqual(path.read_bytes(), before)

    def test_legacy_prepared_scope_masks_and_run_does_not_consume(self):
        from agent_runtime.providers.claude import working_backend
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'synthetic-auth'
            source.write_text('synthetic')
            backend = FakeBackend()
            with patch.dict(os.environ, {'CAS_LOCAL_OWNER_AUTH_FILE': str(source)}):
                store = WorkingSessions(root / 'data', backend=backend, root=root)
                with patch('agent_runtime.tasks.working_sessions.PRIVATE', working_backend.LEGACY_PRIVATE):
                    sid = store.create('Synthetic')['session_id']
                    store.add(sid, title='Task', prompt='accessToken: SYNTHETIC_PRIVATE')
                    row = store.prepare(sid)
                path = store.folder(sid) / 'session.json'
                before = path.read_bytes()
                self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(store.scope(sid)))
                with self.assertRaises(ValueError):
                    store.run(sid, None, allow_live=True)
                self.assertFalse(store._claim(row).exists())
                self.assertEqual(backend.calls, 0)
                self.assertEqual(path.read_bytes(), before)
                store._claim(row).write_text('synthetic-consumed', encoding='utf-8')
                claim = store._claim(row).read_bytes()
                with self.assertRaisesRegex(ValueError, 'NO_REPLAY'):
                    store.run(sid, None, allow_live=True)
                self.assertEqual(store._claim(row).read_bytes(), claim)

    def test_legacy_draft_sensitive_task_cannot_be_prepared(self):
        from agent_runtime.providers.claude import working_backend
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            store = WorkingSessions(root / 'data', backend=FakeBackend(), root=root)
            with patch('agent_runtime.tasks.working_sessions.PRIVATE', working_backend.LEGACY_PRIVATE):
                sid = store.create('Synthetic')['session_id']
                store.add(sid, title='Task', prompt='refreshToken: SYNTHETIC_PRIVATE')
            self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(store.get(sid)))
            with self.assertRaises(ValueError):
                store.prepare(sid)
            self.assertEqual(store.load(sid)['status'], 'DRAFT')
            self.assertFalse(store.bundle(store.load(sid)).exists())

    def test_missing_result_failure_survives_reopen_and_history_without_replay(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'synthetic-auth'
            source.write_text('synthetic')
            with patch.dict(os.environ, {'CAS_LOCAL_OWNER_AUTH_FILE': str(source)}):
                backend = FakeBackend()
                store = WorkingSessions(root / 'data', backend=backend, root=root)
                sid = store.create('Synthetic')['session_id']
                store.add(sid, title='Task', prompt='Synthetic task')
                record = store.prepare(sid)
                evidence = store.bundle(record) / 'runtime-evidence'
                evidence.mkdir()
                outcome = {'attempt': record['attempt_id'], 'result': 'FAIL_OR_INCONCLUSIVE',
                           'no_retry': True, 'stages': {}, 'cleanup_errors': [],
                           'evidence_errors': [], 'cancellation_local_expected': False,
                           'diagnostic': {'work_task': {'native_success': True,
                                                        'selected_text_state': 'EMPTY'}}}
                (evidence / 'outcome.json').write_text(json.dumps(outcome))
                result = DockerWorkingBackend().result(store.bundle(record), record)
                with patch.object(backend, 'run', return_value=result) as execute:
                    done = store.run(sid, None, allow_live=True)
                    self.assertEqual((done['status'], done['code']),
                                     ('FAILED', 'WORKING_SESSION_RESULT_UNAVAILABLE'))
                    reopened = WorkingSessions(root / 'data', backend=backend, root=root)
                    self.assertEqual(reopened.get(sid)['code'], done['code'])
                    self.assertEqual(reopened.list()[0]['session_id'], sid)
                    with self.assertRaisesRegex(ValueError, 'NO_REPLAY'):
                        reopened.run(sid, None, allow_live=True)
                    self.assertEqual(execute.call_count, 1)

    def test_history_orders_newest_first_using_real_instants(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            store = WorkingSessions(root / 'data', backend=FakeBackend(), root=root)
            first = store.create('First')
            second = store.create('Second')
            old = store.load(first['session_id'])
            new = store.load(second['session_id'])
            old['created_at'] = '2026-01-01T12:00:00+03:00'
            new['created_at'] = '2026-01-01T10:00:00+00:00'
            store.save(old)
            store.save(new)
            self.assertEqual([r['session_id'] for r in store.list()],
                             [second['session_id'], first['session_id']])

    def test_history_continues_beyond_twenty_without_deleting_records(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            store = WorkingSessions(root / 'data', backend=FakeBackend(), root=root)
            ids = [store.create('synthetic')['session_id'] for _ in range(21)]
            self.assertEqual({s['session_id'] for s in store.list()}, set(ids))
            self.assertEqual(store.get(ids[0])['status'], 'DRAFT')

    def test_confirmed_cancellation_has_no_failure_code(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = Path(name)
            evidence = bundle / 'runtime-evidence'
            evidence.mkdir()
            record = {'attempt_id': 'synthetic', 'tasks': [{'task_id': 'synthetic'}]}
            outcome = {'attempt': 'synthetic', 'result': 'FAIL_OR_INCONCLUSIVE',
                       'no_retry': True, 'stages': {}, 'cleanup_errors': [],
                       'evidence_errors': [], 'cancellation_local_expected': True}
            (evidence / 'outcome.json').write_text(json.dumps(outcome))
            result = DockerWorkingBackend().result(bundle, record)
            self.assertTrue(result['cancelled'])
            self.assertTrue(result['cleanup_confirmed'])
            self.assertIsNone(result['code'])
            outcome['cleanup_errors'] = [{'reason': 'synthetic'}]
            (evidence / 'outcome.json').write_text(json.dumps(outcome))
            self.assertEqual(DockerWorkingBackend().result(bundle, record)['code'],
                             'WORKING_SESSION_NOT_COMPLETED')

    def test_success_without_selected_text_has_a_clear_failure_code(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = Path(name)
            evidence = bundle / 'runtime-evidence'
            evidence.mkdir()
            record = {'attempt_id': 'synthetic', 'tasks': [{'task_id': 'synthetic'}]}
            outcome = {'attempt': 'synthetic', 'result': 'FAIL_OR_INCONCLUSIVE',
                       'no_retry': True, 'stages': {}, 'cleanup_errors': [],
                       'evidence_errors': [], 'cancellation_local_expected': False,
                       'diagnostic': {'work_task': {'native_success': True,
                                                    'selected_text_state': 'EMPTY'}}}
            (evidence / 'outcome.json').write_text(json.dumps(outcome))
            result = DockerWorkingBackend().result(bundle, record)
            self.assertFalse(result['completed'])
            self.assertEqual(result['code'], 'WORKING_SESSION_RESULT_UNAVAILABLE')

    def test_owner_run_without_approval_file_still_consumes_once(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'synthetic-auth'
            source.write_text('synthetic')
            with patch.dict(os.environ, {'CAS_LOCAL_OWNER_AUTH_FILE': str(source)}):
                backend = FakeBackend()
                store = WorkingSessions(root / 'data', backend=backend, root=root)
                sid = store.create('test')['session_id']
                store.add(sid, title='one', prompt='first synthetic task')
                store.add(sid, title='two', prompt='second synthetic task')
                row = store.prepare(sid)
                self.assertNotIn('--approval', row['local_command'])
                result = store.run(sid, None, allow_live=True)
                self.assertEqual(result['status'], 'COMPLETED')
                self.assertEqual(backend.calls, 1)
                with self.assertRaisesRegex(ValueError, 'NO_REPLAY'):
                    store.run(sid, None, allow_live=True)
                self.assertEqual(backend.calls, 1)

    def test_copy_is_bounded_exclusive_and_leaves_source_intact(self):
        source_code = Path(__file__).resolve().parents[1] / 'src/agent_runtime/providers/claude/working_cells/auth.py'
        spec = importlib.util.spec_from_file_location('local_auth_fixture', source_code)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as name:
            source, dest = Path(name) / 'source', Path(name) / 'dest'
            source.write_bytes(b'synthetic')
            module.copy_local_auth(source, dest)
            self.assertEqual(source.read_bytes(), b'synthetic')
            self.assertEqual(dest.read_bytes(), b'synthetic')
            with self.assertRaises(FileExistsError):
                module.copy_local_auth(source, dest)
            dest.unlink()
            source.write_bytes(b'x' * 65537)
            with self.assertRaises(ValueError):
                module.copy_local_auth(source, dest)
            self.assertFalse(dest.exists())

    def test_mode_is_bound_to_frozen_plan_and_does_not_assert_billing_setting(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'synthetic-auth'
            source.write_text('synthetic')
            with patch.dict(os.environ, {'CAS_LOCAL_OWNER_AUTH_FILE': str(source)}):
                store = WorkingSessions(root / 'data', root=root)
                sid = store.create('test')['session_id']
                store.add(sid, title='test', prompt='synthetic')
                row = store.prepare(sid)
                backend = DockerWorkingBackend()
                policy = backend.verify(store.bundle(row), row)
                self.assertEqual(policy['local_auth_file'], str(source))
                self.assertFalse(backend.approval(row, row['plan_hash'], True)['extra_usage_disabled'])
                with patch.dict(os.environ, {}, clear=True):
                    with self.assertRaisesRegex(ValueError, 'AUTH_MODE_CHANGED'):
                        backend.verify(store.bundle(row), row)


if __name__ == '__main__':
    unittest.main()
