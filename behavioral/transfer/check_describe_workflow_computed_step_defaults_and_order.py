"""describe-workflow-computed-step-defaults-and-order."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "describe-workflow-computed-step-defaults-and-order"
GROUP = 'lifecycle'
SERVICES = ['transfer']

# smithy WorkflowId pattern, com.amazonaws.transfer#WorkflowId.
_WORKFLOW_ID_RE = re.compile(r'^w-[a-z0-9]{17}$')

# The listed (projected) workflow shape — com.amazonaws.transfer#ListedWorkflow.
_LISTED_KEYS = {'Arn', 'Description', 'WorkflowId'}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeWorkflow replays steps in submission order and fills in service-computed defaults
    (SourceFileLocation, OverwriteExisting); ListWorkflows returns only Arn/Description/WorkflowId.
    """
    tf = ctx.client('transfer')

    # A workflow definition is validated structurally; the destination bucket is resolved at
    # execution time, so no S3 bucket is created here. Name satisfies smithy S3Bucket.
    bucket = ctx.unique_name('sim2real-behav-wf-')
    steps = [
        {'Type': 'TAG', 'TagStepDetails': {
            'Name': 'step-tag', 'Tags': [{'Key': 'sim2real', 'Value': 'behav'}]}},
        {'Type': 'COPY', 'CopyStepDetails': {
            'Name': 'step-copy',
            'DestinationFileLocation': {'S3FileLocation': {'Bucket': bucket, 'Key': 'processed/'}}}},
        {'Type': 'DELETE', 'DeleteStepDetails': {'Name': 'step-delete'}},
    ]
    wid = tf.create_workflow(
        Description='sim2real-behav ordered workflow',
        Steps=steps,
        OnExceptionSteps=[{'Type': 'DELETE', 'DeleteStepDetails': {'Name': 'on-exception'}}],
    )['WorkflowId']
    ctx.on_cleanup(lambda _w=wid: tf.delete_workflow(WorkflowId=_w))

    assert _WORKFLOW_ID_RE.match(wid), f"WorkflowId {wid!r} violates ^w-[a-z0-9]{{17}}$"

    wf = tf.describe_workflow(WorkflowId=wid)['Workflow']
    assert wf['WorkflowId'] == wid, wf
    assert wf['Description'] == 'sim2real-behav ordered workflow', wf.get('Description')
    assert f':workflow/{wid}' in wf['Arn'], wf['Arn']

    # Step order is the execution order, so it is compared as a list, not a set.
    got_order = [s['Type'] for s in wf.get('Steps', [])]
    assert got_order == ['TAG', 'COPY', 'DELETE'], (
        f"DescribeWorkflow must replay steps in submission order; got {got_order}"
    )
    got_names = [
        (s.get('TagStepDetails') or s.get('CopyStepDetails') or s.get('DeleteStepDetails'))['Name']
        for s in wf['Steps']
    ]
    assert got_names == ['step-tag', 'step-copy', 'step-delete'], got_names

    # Service-computed defaults the request never carried.
    copy_details = wf['Steps'][1]['CopyStepDetails']
    assert copy_details.get('SourceFileLocation') == '${previous.file}', (
        f"COPY step SourceFileLocation must default to '${{previous.file}}', "
        f"got {copy_details.get('SourceFileLocation')!r}"
    )
    assert copy_details.get('OverwriteExisting') == 'FALSE', (
        f"COPY step OverwriteExisting must default to 'FALSE', "
        f"got {copy_details.get('OverwriteExisting')!r}"
    )
    tag_details = wf['Steps'][0]['TagStepDetails']
    assert tag_details.get('SourceFileLocation') == '${previous.file}', (
        f"TAG step SourceFileLocation must default to '${{previous.file}}', "
        f"got {tag_details.get('SourceFileLocation')!r}"
    )
    assert [t['Key'] for t in tag_details.get('Tags') or []] == ['sim2real'], tag_details

    on_exc = wf.get('OnExceptionSteps') or []
    assert [s['Type'] for s in on_exc] == ['DELETE'], (
        f"OnExceptionSteps must round-trip as [DELETE], got {[s.get('Type') for s in on_exc]}"
    )
    assert on_exc[0]['DeleteStepDetails']['Name'] == 'on-exception', on_exc
    assert on_exc[0]['DeleteStepDetails'].get('SourceFileLocation') == '${previous.file}', (
        f"OnExceptionSteps entries get the same computed default: {on_exc[0]}"
    )
    assert wf.get('Tags') == [], f"untagged workflow must describe Tags as [], got {wf.get('Tags')!r}"

    # ListWorkflows is a projection and must not return Steps.
    listed = [w for w in tf.list_workflows().get('Workflows', []) if w['WorkflowId'] == wid]
    assert len(listed) == 1, f"ListWorkflows must contain exactly one entry for {wid}: {listed}"
    extra = set(listed[0]) - _LISTED_KEYS
    assert not extra, (
        f"ListWorkflows must project to {sorted(_LISTED_KEYS)} only; extra members {sorted(extra)} "
        f"leak the full definition"
    )
    assert listed[0]['Description'] == 'sim2real-behav ordered workflow', listed[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
