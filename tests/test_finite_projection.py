import copy
import json
import unittest
from unittest.mock import patch
from agent_runtime.tasks import finite_projection as p
from agent_runtime.tasks import working_sessions as ws
import test_working_sessions as base

class ProjectionTests(unittest.TestCase):
    setUp=base.Tests.setUp
    prepared=base.Tests.prepared
    approval=base.Tests.approval
    def fixture(self):
        d=self.prepared()
        d=self.store.load(d['session_id'])
        claim={'attempt':d['attempt_id'],'manifest_sha256':d['plan_hash'],'state':'CONSUMED_NO_REPLAY'}
        ws.atomic_json(self.store._claim(d),claim)
        d.update(schema_version=2,status='STARTING',cleanup='PENDING',projection=p.empty())
        self.store.save(d)
        return d
    def test_gate_and_v1_read(self):
        self.assertFalse(p.enabled())
        d=self.store.create('synthetic')
        path=self.store.folder(d['session_id'])/'session.json'
        before=path.read_bytes()
        self.store.get(d['session_id'])
        self.assertEqual(before,path.read_bytes())
        with self.assertRaises(PermissionError): self.store._issue_finite_callback(d)
    def test_bounds_terminal_and_privacy(self):
        x=p.empty()
        for _ in range(p.MAX_EVENTS): x=p.append(x,'status_observed','RUNNING')
        x=p.append(x,'stage_completed','first')
        x=p.append(x,'terminal','COMPLETED')
        self.assertEqual(x['state'],{'stages':['first'],'terminal':'COMPLETED'})
        self.assertEqual(x['truncation']['omitted_count'],2)
        self.assertEqual(x['truncation']['upstream_completeness'],'unknown')
        p.validate(json.loads(json.dumps(x)))
        with self.assertRaises(ValueError): p.append(x,'status_observed','RUNNING')
        bad=copy.deepcopy(x); bad['truncation']['omitted_count']=1
        with self.assertRaises(ValueError): p.validate(bad)
        bad=copy.deepcopy(x); bad['raw_payload']='secret'
        with self.assertRaises(ValueError): p.validate(bad)
    def test_callback_binding_stale_and_latch(self):
        with patch.object(p,'enabled',return_value=True):
            d=self.fixture(); emit,fault=self.store._issue_finite_callback(d)
            emit('first',d['tasks'][0]['run_id'])
            current=self.store.load(d['session_id'])
            self.assertEqual(current['projection']['state']['stages'],['first'])
            self.assertNotIn('projection',self.store.view(current))
            self.assertNotIn(d['tasks'][0]['run_id'],json.dumps(current['projection']))
            with self.assertRaises(ValueError): emit('second','wrong')
            self.assertTrue(fault['uncertain'])
            with self.assertRaises(ValueError): emit('second',d['tasks'][1]['run_id'])
    def test_cancel_intent_never_replaced_by_callback(self):
        with patch.object(p,'enabled',return_value=True):
            d=self.fixture(); emit,_=self.store._issue_finite_callback(d)
            d=self.store.load(d['session_id']); d['status']='CANCEL_REQUESTED'; self.store.save(d)
            emit('first',d['tasks'][0]['run_id'])
            self.assertEqual(self.store.load(d['session_id'])['status'],'CANCEL_REQUESTED')
    def test_terminal_late_and_recovery_gate(self):
        with patch.object(p,'enabled',return_value=True):
            d=self.fixture(); emit,_=self.store._issue_finite_callback(d)
            d['status']='INTERRUPTED'; d['cleanup']='UNCONFIRMED'
            d['projection']=p.append(d['projection'],'terminal','INTERRUPTED'); self.store.save(d)
            with self.assertRaises(ValueError): emit('first',d['tasks'][0]['run_id'])
            self.assertEqual(self.store.load(d['session_id'])['projection']['state']['terminal'],'INTERRUPTED')
    def test_fault_after_replace_no_replay(self):
        with patch.object(p,'enabled',return_value=True):
            d=self.fixture(); emit,fault=self.store._issue_finite_callback(d)
            real=ws.atomic_json
            def after(*args):
                real(*args); raise OSError('synthetic uncertain replacement')
            with patch.object(ws,'atomic_json',side_effect=after):
                with self.assertRaises(ValueError): emit('first',d['tasks'][0]['run_id'])
            self.assertTrue(fault['uncertain'])
            with self.assertRaises(ValueError): emit('first',d['tasks'][0]['run_id'])
            self.assertEqual(self.store.load(d['session_id'])['projection']['state']['stages'],['first'])

    def test_real_owner_path_with_fake_backend(self):
        class CallbackBackend(base.FakeBackend):
            def run(self,bundle,record,approval,*,projection_callback=None):
                self.verify(bundle,record)
                projection_callback('first',record['tasks'][0]['run_id'])
                projection_callback('second',record['tasks'][1]['run_id'])
                return dict(completed=True,cleanup_confirmed=True,cancelled=False,
                            stages=[base.report(record,0),base.report(record,1)],code=None)
        self.store.backend=CallbackBackend(); self.backend=self.store.backend
        with patch.object(p,'enabled',return_value=True):
            d=self.prepared()
            with patch('sys.stdin.isatty',return_value=True), patch('sys.stdout.isatty',return_value=True), patch('sys.stderr.isatty',return_value=True):
                result=self.store.run(d['session_id'],self.approval(d),allow_live=True)
            self.assertEqual(result['status'],'COMPLETED')
            self.assertNotIn('projection',result)
            stored=self.store.load(d['session_id'])
            self.assertEqual(stored['projection']['state'],{'stages':['first','second'],'terminal':'COMPLETED'})
    def test_stale_plan_and_restart(self):
        with patch.object(p,'enabled',return_value=True):
            d=self.fixture(); emit,fault=self.store._issue_finite_callback(d)
            claim=self.store._claim(d); claim.write_text('{}')
            with self.assertRaises(ValueError): emit('first',d['tasks'][0]['run_id'])
            self.assertTrue(fault['uncertain'])
            ws.atomic_json(claim,{'attempt':d['attempt_id'],'manifest_sha256':d['plan_hash'],'state':'CONSUMED_NO_REPLAY'})
            self.store.recover(d['session_id'])
            d=self.store.load(d['session_id'])
            self.assertEqual((d['status'],d['cleanup']),('INTERRUPTED','UNCONFIRMED'))
            self.assertEqual(d['projection']['state']['terminal'],'INTERRUPTED')
    def test_closed_gate_blocks_v2_recovery_and_writes(self):
        with patch.object(p,'enabled',return_value=True): d=self.fixture()
        path=self.store.folder(d['session_id'])/'session.json'; before=path.read_bytes()
        with self.assertRaises(PermissionError): self.store.recover(d['session_id'])
        self.assertEqual(before,path.read_bytes())
        with self.assertRaises(PermissionError): self.store.save(d)
    def test_truncated_stages_remain_ordered_and_unique(self):
        x=p.empty()
        for _ in range(p.MAX_EVENTS): x=p.append(x,'status_observed','RUNNING')
        x=p.append(x,'stage_completed','first'); x=p.append(x,'stage_completed','second')
        with self.assertRaises(ValueError): p.append(x,'stage_completed','second')
        self.assertEqual(x['state']['stages'],['first','second'])

    def test_plan_attempt_claim_changes_reject_and_latch(self):
        for key in ('plan_hash','attempt_id','claim'):
            with self.subTest(key=key), patch.object(p,'enabled',return_value=True):
                d=self.fixture(); emit,fault=self.store._issue_finite_callback(d)
                if key=='claim': self.store._claim(d).write_text('{}')
                else:
                    d[key]=('a'*64 if key=='plan_hash' else '00000000-0000-4000-8000-000000000000')
                    self.store.save(d)
                with self.assertRaises(ValueError): emit('first',d['tasks'][0]['run_id'])
                self.assertTrue(fault['uncertain'])
    def test_ending_and_reopen(self):
        with patch.object(p,'enabled',return_value=True):
            d=self.fixture(); emit,_=self.store._issue_finite_callback(d)
            d['status']='ENDING'; self.store.save(d)
            emit('first',d['tasks'][0]['run_id'])
            other=ws.WorkingSessions(self.root,backend=self.backend,root=self.root)
            self.assertEqual(other.load(d['session_id'])['status'],'ENDING')
            other.recover(d['session_id'])
            self.assertEqual(other.load(d['session_id'])['projection']['state']['terminal'],'INTERRUPTED')
            with self.assertRaises(ValueError): emit('second',d['tasks'][1]['run_id'])
    def test_callback_uses_latched_stage_after_truncation(self):
        with patch.object(p,'enabled',return_value=True):
            d=self.fixture()
            for _ in range(p.MAX_EVENTS): d['projection']=p.append(d['projection'],'status_observed','RUNNING')
            self.store.save(d); emit,_=self.store._issue_finite_callback(d)
            emit('first',d['tasks'][0]['run_id']); emit('second',d['tasks'][1]['run_id'])
            self.assertEqual(self.store.load(d['session_id'])['projection']['state']['stages'],['first','second'])
