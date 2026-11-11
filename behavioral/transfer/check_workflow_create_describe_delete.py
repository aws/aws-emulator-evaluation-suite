"""workflow-create-describe-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "workflow-create-describe-delete"
GROUP = 'lifecycle'
SERVICES = ['transfer']

@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A created workflow describes with its COPY step and no executions; after DeleteWorkflow,
    both DescribeWorkflow and a second delete are ResourceNotFoundException."""
    tf = ctx.client('transfer')
    wid = tf.create_workflow(Description='behav workflow', Steps=[{'Type': 'COPY', 'CopyStepDetails': {'Name': 'copy-step', 'DestinationFileLocation': {'S3FileLocation': {'Bucket': ctx.unique_name('sim2real-behav-wf-bkt-'), 'Key': 'processed/'}}}}], OnExceptionSteps=[{'Type': 'DELETE', 'DeleteStepDetails': {'Name': 'delete-on-exception'}}])['WorkflowId']
    ctx.on_cleanup(lambda _k=wid: _safe_delete_workflow(tf, _k))
    wf = tf.describe_workflow(WorkflowId=wid)['Workflow']
    assert wf['WorkflowId'] == wid, wf
    assert f':workflow/{wid}' in wf['Arn'], wf['Arn']
    step_types = {s['Type'] for s in wf.get('Steps', [])}
    assert 'COPY' in step_types, wf.get('Steps')
    execs = tf.list_executions(WorkflowId=wid)
    assert execs.get('Executions') == [], execs.get('Executions')

    tf.delete_workflow(WorkflowId=wid)
    code, message = _error(lambda: tf.describe_workflow(WorkflowId=wid))
    assert code == 'ResourceNotFoundException', f'expected 404 on Describe after Delete, got {code}'
    assert message == 'Unknown workflow', f"expected message 'Unknown workflow', got {message!r}"
    code2, message2 = _error(lambda: tf.delete_workflow(WorkflowId=wid))
    assert code2 == 'ResourceNotFoundException', f'expected 404 on a second Delete of the dead id, got {code2}'
    assert message2 == 'Unknown workflow', f"expected message 'Unknown workflow', got {message2!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_workflow(tf, workflow_id: str) -> None:
    try:
        tf.delete_workflow(WorkflowId=workflow_id)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
