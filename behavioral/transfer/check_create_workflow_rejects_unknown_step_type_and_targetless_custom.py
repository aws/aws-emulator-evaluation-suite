"""create-workflow-rejects-unknown-step-type-and-targetless-custom."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-workflow-rejects-unknown-step-type-and-targetless-custom"
GROUP = 'overly-permissive'
SERVICES = ['transfer']


def _err(fn):
    """Return (code, message) for a ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message') or ''
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_workflow_if_present(tf, workflow_id):
    """Teardown for a workflow the body may already have deleted."""
    try:
        tf.delete_workflow(WorkflowId=workflow_id)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise


def _workflow_ids(tf, descriptions=None):
    """Every listed workflow id, or only those whose Description is one of descriptions."""
    out = set()
    for page in tf.get_paginator('list_workflows').paginate():
        for w in page.get('Workflows', []):
            if descriptions is None or w.get('Description') in descriptions:
                out.add(w['WorkflowId'])
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkflow rejects an unknown step Type (ValidationException) and a targetless CUSTOM
    step (InvalidRequestException) with distinct exact messages and persists neither, while the
    valid baseline is created, described and deleted.
    """
    tf = ctx.client('transfer')

    bucket = ctx.unique_name('sim2real-behav-wf-')
    baseline = [{'Type': 'COPY', 'CopyStepDetails': {
        'Name': 'step-copy',
        'DestinationFileLocation': {'S3FileLocation': {'Bucket': bucket, 'Key': 'processed/'}},
    }}]

    bad_type_description = f'{bucket} bad type'
    no_target_description = f'{bucket} no target'

    # Break exactly one thing: the step Type is outside the WorkflowStepType enum.
    bad_type = [dict(baseline[0], Type='ENCRYPT')]
    code_type, msg_type = _err(
        lambda: tf.create_workflow(Description=bad_type_description, Steps=bad_type)
    )
    assert code_type == 'ValidationException', (
        f"CreateWorkflow with Type='ENCRYPT' (outside WorkflowStepType) must be rejected with "
        f"ValidationException, got {code_type!r}: {msg_type!r}"
    )
    assert msg_type == (
        "1 validation error detected: Value at 'steps.1.member.type' failed to satisfy constraint: "
        "Member must satisfy enum value set: [DELETE, DECRYPT, CUSTOM, COPY, TAG]"
    ), f"unexpected unknown-step-type message: {msg_type!r}"

    # Break exactly one thing: a CUSTOM step with no Lambda Target.
    no_target = [{'Type': 'CUSTOM', 'CustomStepDetails': {'Name': 'step-custom'}}]
    code_target, msg_target = _err(
        lambda: tf.create_workflow(Description=no_target_description, Steps=no_target)
    )
    assert code_target == 'InvalidRequestException', (
        f"CreateWorkflow with a CUSTOM step and no Target must be rejected with "
        f"InvalidRequestException, got {code_target!r}: {msg_target!r}"
    )
    assert msg_target == 'Invalid function provided', (
        f"unexpected targetless-CUSTOM message: {msg_target!r}"
    )

    # Transfer funnels most semantic errors into InvalidRequestException, so the two defects
    # must at least carry distinct messages.
    assert msg_type and msg_target and msg_type != msg_target, (
        f"two different definition defects produced indistinguishable diagnostics: "
        f"{msg_type!r} vs {msg_target!r}"
    )

    # Effect absent: neither rejected definition was persisted.
    leaked = _workflow_ids(tf, {bad_type_description, no_target_description})
    assert leaked == set(), f"rejected workflow definitions leaked: {sorted(leaked)}"

    # Control: the same definition with the one broken field fixed is accepted, is listed,
    # and deletes cleanly.
    wid = tf.create_workflow(
        Description='sim2real-behav control', Steps=baseline,
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )['WorkflowId']
    ctx.on_cleanup(lambda _w=wid: _delete_workflow_if_present(tf, _w))
    assert wid in _workflow_ids(tf), f"control workflow {wid} absent from ListWorkflows"
    control_type = tf.describe_workflow(WorkflowId=wid)['Workflow']['Steps'][0]['Type']
    assert control_type == 'COPY', (
        f"control workflow {wid} must describe the COPY step it was created with, got {control_type!r}"
    )

    tf.delete_workflow(WorkflowId=wid)
    code_gone, msg_gone = _err(lambda: tf.describe_workflow(WorkflowId=wid))
    assert code_gone == 'ResourceNotFoundException', (
        f"DescribeWorkflow after delete must raise ResourceNotFoundException, got {code_gone!r}"
    )
    assert msg_gone == 'Unknown workflow', f"unexpected not-found message: {msg_gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
