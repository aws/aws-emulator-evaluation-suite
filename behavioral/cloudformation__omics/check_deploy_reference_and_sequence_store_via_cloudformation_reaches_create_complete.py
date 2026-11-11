"""deploy-reference-and-sequence-store-via-cloudformation-reaches-create-complete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-reference-and-sequence-store-via-cloudformation-reaches-create-complete"
GROUP = "deploy"
SERVICES = ["cloudformation", "omics"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_REF_GONE = ("ResourceNotFoundException", "The specified reference store does not exist.")
_SEQ_GONE = ("ResourceNotFoundException", "The specified sequence store does not exist.")


def _stores_named(omics, op: str, key: str, name: str) -> list[dict]:
    """Every store ``op`` returns named ``name``, read through every page."""
    return [s for s in paginate(omics, op, key, filter={"name": name}) if s.get("name") == name]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation-deployed AWS::Omics::ReferenceStore and AWS::Omics::SequenceStore are
    real HealthOmics stores (Ref equals the store id, GetAtt matches the describe calls, the S3
    access point carries a readable policy) and DeleteStack really removes both."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    omics = ctx.client("omics")
    stack_name = ctx.unique_name("sim2real-xsvc-stk-")
    ref_name = ctx.unique_name("sim2real-xsvc-refstore-")
    seq_name = ctx.unique_name("sim2real-xsvc-seqstore-")

    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Sim2RealRefStore:
    Type: AWS::Omics::ReferenceStore
    Properties:
      Name: {ref_name}
  Sim2RealSeqStore:
    Type: AWS::Omics::SequenceStore
    Properties:
      Name: {seq_name}
Outputs:
  RefStoreId:
    Value: !Ref Sim2RealRefStore
  RefStoreArn:
    Value: !GetAtt Sim2RealRefStore.Arn
  SeqStoreId:
    Value: !Ref Sim2RealSeqStore
  SeqStoreArn:
    Value: !GetAtt Sim2RealSeqStore.Arn
  SeqStoreS3Uri:
    Value: !GetAtt Sim2RealSeqStore.S3Uri
  SeqStoreAccessPointArn:
    Value: !GetAtt Sim2RealSeqStore.S3AccessPointArn
"""

    stack_id = create_stack(ctx, cfn, stack_name, template)
    status = wait_stack(cfn, stack_id, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", (
        f"Stack {stack_name} ended in {status}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    ref_id = outputs["RefStoreId"]
    seq_id = outputs["SeqStoreId"]

    ref_listed = [r["id"] for r in _stores_named(omics, "list_reference_stores", "referenceStores", ref_name)]
    assert ref_listed == [ref_id], (
        f"expected Ref {ref_id!r} to be the one reference store HealthOmics lists under "
        f"{ref_name!r}, got {ref_listed!r}"
    )
    ref_described = omics.get_reference_store(id=ref_id)
    assert ref_described["arn"] == outputs["RefStoreArn"], (
        f"expected GetAtt Arn {outputs['RefStoreArn']!r}, got {ref_described['arn']!r}"
    )
    assert ref_described["name"] == ref_name, f"expected name {ref_name!r}, got {ref_described['name']!r}"

    seq_listed = [r["id"] for r in _stores_named(omics, "list_sequence_stores", "sequenceStores", seq_name)]
    assert seq_listed == [seq_id], (
        f"expected Ref {seq_id!r} to be the one sequence store HealthOmics lists under "
        f"{seq_name!r}, got {seq_listed!r}"
    )
    seq_described = omics.get_sequence_store(id=seq_id)
    assert seq_described["arn"] == outputs["SeqStoreArn"], (
        f"expected GetAtt Arn {outputs['SeqStoreArn']!r}, got {seq_described['arn']!r}"
    )
    assert seq_described["name"] == seq_name, f"expected name {seq_name!r}, got {seq_described['name']!r}"
    assert seq_described["s3Access"]["s3Uri"] == outputs["SeqStoreS3Uri"], (
        f"expected GetAtt S3Uri {outputs['SeqStoreS3Uri']!r}, got {seq_described['s3Access']['s3Uri']!r}"
    )
    access_point_arn = outputs["SeqStoreAccessPointArn"]
    assert seq_described["s3Access"]["s3AccessPointArn"] == access_point_arn, (
        f"expected GetAtt S3AccessPointArn {access_point_arn!r}, "
        f"got {seq_described['s3Access']['s3AccessPointArn']!r}"
    )

    policy = omics.get_s3_access_policy(s3AccessPointArn=access_point_arn)
    assert policy["storeId"] == seq_id, f"expected policy storeId {seq_id!r}, got {policy['storeId']!r}"
    assert policy["storeType"] == "SEQUENCE_STORE", (
        f"expected policy storeType 'SEQUENCE_STORE', got {policy['storeType']!r}"
    )

    delete_stack(cfn, stack_id)
    expect_error(lambda: omics.get_reference_store(id=ref_id), *_REF_GONE)
    expect_error(lambda: omics.get_sequence_store(id=seq_id), *_SEQ_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
