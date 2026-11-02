"""Nonzero work diagnostics and cleanup facts on real controller/core, heap-only I/O."""
import copy,json,threading,types,unittest
from unittest.mock import patch
from test_working_lifecycle import LifecycleTests
from test_working_sessions import report


class WorkFailureTests(unittest.TestCase):
    task_count=1
    setUp=LifecycleTests.setUp
    unload=LifecycleTests.unload
    job=LifecycleTests.job

    def raw(self, *, rc=1, failure=None, doc=None, stderr=b''):
        doc=report(self.record,0) if doc is None else doc
        return dict(rc=rc,out=json.dumps(doc).encode(),err=stderr,failure=failure,elapsed=1,
                    client_cleanup=dict(client_stopped=True,capture_complete=True,capture_overflow=False,
                                        explicit_cancel=False,peer_lost=False,cancel_terminated_client=False))

    def failed(self):
        return report(self.record,0)|dict(result='FAIL',native_success=False,text='',failure_code='EXECUTION_NOT_ACCEPTED')

    def nonzero_flow(self, *, removal_failure=False):
        normal=self.fake.finish
        self.fake.evidence=self.bundle;self.fake.bytes=0;self.fake.prefix=['fixed-docker'];self.fake.evidence_errors=[]
        def finish(job,seconds,guard=lambda:True):
            if job.role in {'work_a','work_b'}:
                if not getattr(job,'fixed_work',False):
                    direct=self.job(rc=1,cancel=False);direct.out=bytearray(json.dumps(self.failed()).encode())
                    direct.receipt_number=self.fake.number;direct.process.stdin=job.process.stdin
                    job.__dict__.update(direct.__dict__)
                    job.poll=types.MethodType(self.core.Job.poll,job)
                    job.output=types.MethodType(self.core.Job.output,job)
                    job.finish=types.MethodType(self.core.Job.finish,job)
                    self.work_job=job
                return self.core.Docker.finish(self.fake,job,seconds,guard)
            return normal(job,seconds,guard)
        self.fake.finish=finish
        with self.assertRaisesRegex(self.core.Failure,'WORK_CLIENT_NONZERO') as error:self.runner.execute()
        self.runner.note_failure(error.exception)
        receipt=self.bundle/f'{self.work_job.receipt_number:02}.json';original=receipt.read_bytes()
        if removal_failure:
            def refuse(role):raise self.core.Failure('synthetic-work-absence-unknown')
            self.runner.remove_work=refuse
        self.runner.cleanup()
        self.assertEqual(receipt.read_bytes(),original)
        self.assertEqual(self.runner.reports,{})
        self.assertEqual(self.fake.go_count,1)
        self.assertFalse(self.runner.cancel_cleanup_authorized)
        return json.loads(original)

    def test_nonzero_confirmed_exit_whole_cleanup_stays_failure_but_not_unconfirmed(self):
        receipt=self.nonzero_flow()
        self.assertEqual(self.runner.cleanup_errors,[])
        self.assertTrue(all(not objects for objects in self.fake.objects.values()))
        self.assertEqual(receipt['failure'],'WORK_CLIENT_NONZERO')
        self.assertEqual(receipt['work_projection']['task']['reported_result'],'FAIL')
        self.assertEqual(receipt['out_bytes'],0);self.assertEqual(receipt['err_bytes'],0)

    def test_resource_cleanup_failure_never_suppressed(self):
        self.nonzero_flow(removal_failure=True)
        self.assertTrue(any(v.get('reason')=='WORK_CLEANUP_UNCONFIRMED' for v in self.runner.cleanup_errors))
        self.assertTrue(any(v.get('reason')=='CAPTURE_OR_TERMINATION_UNCONFIRMED' for v in self.runner.cleanup_errors))
        self.assertTrue(self.fake.objects['container'])

    def test_nonzero_metadata_is_finite_and_has_no_error_text_or_ids(self):
        source=self.failed()|{'text':'Ordinary selected text'}
        value=self.controller.safe_work.sanitize(self.raw(doc=source,stderr=b'password=FAKE_PRIVATE_STDERR'),'first')
        meta=value['work_projection']['task']
        self.assertEqual(set(meta),{'reported_result','native_success','tree_empty','declared_query_count','failure_code','selected_text_state'})
        self.assertEqual(meta['declared_query_count'],1)
        self.assertEqual(value['out'],b'');self.assertEqual(value['err'],b'')
        serialized=json.dumps(value['work_projection'])
        for forbidden in ('Ordinary selected text','FAKE_PRIVATE_STDERR',source['session_hash'],source['run_id']):self.assertNotIn(forbidden,serialized)

    def test_invalid_or_sensitive_summary_does_not_gain_diagnostics(self):
        for doc in (self.failed()|{'text':'password=FAKE_PRIVATE_TEXT'},self.failed()|{'text':'x'*4097},self.failed()|{'unknown':'FAKE_PRIVATE_FIELD'}):
            value=self.controller.safe_work.sanitize(self.raw(doc=doc),'first')
            self.assertIsNone(value['work_projection']['task']);self.assertEqual(value['out'],b'')
        value=self.raw();value['out']=b'{"incomplete":'
        self.assertIsNone(self.controller.safe_work.sanitize(value,'first')['work_projection']['task'])

    def test_rc0_behavior_and_nonzero_pass_payload_never_promote_execution(self):
        source=report(self.record,0)
        ok=self.controller.safe_work.sanitize(self.raw(rc=0,doc=source),'first')
        self.assertIsNone(ok['failure']);self.assertEqual(json.loads(ok['out']),source)
        bad=self.controller.safe_work.sanitize(self.raw(rc=1,doc=source),'first')
        self.assertEqual(bad['failure'],'WORK_CLIENT_NONZERO');self.assertEqual(bad['out'],b'')
        self.assertEqual(bad['work_projection']['task']['reported_result'],'PASS')

    def recorded_job(self, *, failure=None):
        job=self.job(rc=1,cancel=False)
        job.recorded_result=self.controller.safe_work.sanitize(self.raw(failure=failure,doc=self.failed()),'first')
        return job

    def check_client(self,job,*,writers=True,error=None):
        error=error or self.core.Failure(job.recorded_result['failure'],job.receipt_number)
        return self.runner.completed_failed_work_client(job,error,writers)

    def test_unknown_exit_and_unknown_poll_fail_closed(self):
        job=self.recorded_job();job.process.rc=None
        self.assertFalse(self.check_client(job))
        job.process.rc=False;self.assertFalse(self.check_client(job))
        def broken():raise OSError('FAKE_PRIVATE_NOT_EXPORTED')
        job.poll=broken;self.assertFalse(self.check_client(job))

    def test_incomplete_overflow_live_threads_and_evidence_errors_fail_closed(self):
        for key,val in (('client_stopped',False),('capture_complete',False),('capture_overflow',True)):
            job=self.recorded_job();job.recorded_result['client_cleanup'][key]=val
            self.assertFalse(self.check_client(job))
        job=self.recorded_job();job.overflow=True;self.assertFalse(self.check_client(job))
        job=self.recorded_job();job.threads=[types.SimpleNamespace(is_alive=lambda:True)];self.assertFalse(self.check_client(job))
        job=self.recorded_job();job.recorded_result['evidence_write_failed']=True;self.assertFalse(self.check_client(job))

    def test_only_matching_recorded_failure_and_owned_absence_can_confirm(self):
        job=self.recorded_job();self.assertTrue(self.check_client(job))
        self.assertFalse(self.check_client(job,writers=False))
        self.assertFalse(self.check_client(job,error=self.core.Failure('WORK_CLIENT_NONZERO',99)))
        self.assertFalse(self.check_client(job,error=self.core.Failure('evidence-write-failed',1)))
        self.assertFalse(self.check_client(job,error=RuntimeError('WORK_CLIENT_NONZERO')))
        job.fixed_work=False;self.assertFalse(self.check_client(job))

    def test_confirmed_timeout_cleanup_is_not_task_success_or_expected_cancel(self):
        job=self.recorded_job(failure='client-timeout')
        self.assertTrue(self.check_client(job))
        self.assertEqual(job.recorded_result['failure'],'WORK_TIMEOUT')
        self.runner.cancel_cleanup_authorized=True
        self.assertFalse(self.runner.expected_cancel_client(job,True))

    def test_capture_or_termination_transport_uncertainty_never_confirmed(self):
        for failure in ('capture-overflow','capture-incomplete','client-termination-unconfirmed','foreign-failure'):
            job=self.recorded_job(failure=failure)
            self.assertFalse(self.check_client(job))

    def test_safe_outcome_diagnostic_revalidates_metadata_and_excludes_foreign_fields(self):
        value=self.controller.safe_work.sanitize(self.raw(doc=self.failed()),'first')
        receipt=dict(argv=['fixed-docker','start','--attach','a'*64],rc=1,capture='FIXED_WORK_SUMMARY',work_projection=value['work_projection'])
        error=self.core.Failure('WORK_CLIENT_NONZERO',1)
        diag=self.controller.diagnostics.safe_failure(error,'sdk',1,receipt,b'password=FAKE_PRIVATE_STDERR')
        self.assertEqual(diag['work_task'],value['work_projection']['task'])
        self.assertNotIn('FAKE_PRIVATE',json.dumps(diag))
        metadata=copy.deepcopy(value['work_projection']['task'])
        for change in ({'extra':'FAKE_PRIVATE'}, {'reported_result':[]},{'failure_code':[]},{'declared_query_count':True}):
            receipt['work_projection']['task']=metadata|change
            diag=self.controller.diagnostics.safe_failure(error,'sdk',1,receipt)
            self.assertNotIn('work_task',diag)

    def test_failed_backend_outcome_cleanup_true_stays_not_completed(self):
        from agent_runtime.providers.claude.working_backend import DockerWorkingBackend
        folder=self.bundle/'runtime-evidence';folder.mkdir()
        (folder/'outcome.json').write_text(json.dumps(dict(attempt=self.record['attempt_id'],result='FAIL_OR_INCONCLUSIVE',no_retry=True,stages={},cleanup_errors=[],evidence_errors=[],reason='Failure')))
        result=DockerWorkingBackend().result(self.bundle,self.record)
        self.assertFalse(result['completed']);self.assertTrue(result['cleanup_confirmed']);self.assertFalse(result['cancelled'])

    def test_product_failed_with_confirmed_cleanup_persists_without_replay(self):
        from test_working_sessions import FakeBackend,WorkingSessions
        backend=FakeBackend();root=self.bundle.parents[2]
        store=WorkingSessions(root,backend=backend,root=root)
        approval=self.bundle.parent/'synthetic-offline-approval.json'
        approval.write_text(json.dumps(backend.approval(self.record,self.record['plan_hash'],True)))
        outcome=dict(completed=False,cleanup_confirmed=True,cancelled=False,stages=[],code='WORKING_SESSION_NOT_COMPLETED')
        with patch.object(backend,'run',return_value=outcome) as run,patch('sys.stdin.isatty',return_value=True),patch('sys.stdout.isatty',return_value=True),patch('sys.stderr.isatty',return_value=True):
            result=store.run(self.record['session_id'],approval,allow_live=True)
            self.assertEqual((result['status'],result['cleanup'],result['results']),('FAILED','CONFIRMED',[]))
            with self.assertRaisesRegex(ValueError,'NO_REPLAY'):store.run(self.record['session_id'],approval,allow_live=True)
            self.assertEqual(run.call_count,1)
        self.assertEqual(store.get(self.record['session_id'])['status'],'FAILED')


del LifecycleTests

if __name__=='__main__':
    with patch('subprocess.Popen',side_effect=AssertionError('NO_PROCESS')),patch('socket.socket',side_effect=AssertionError('NO_SOCKET')):unittest.main(verbosity=2)
