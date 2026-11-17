"""cfn-s3vectors-index-dimension-change-without-indexname-replaces-and-deletes-original."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3vectors-index-dimension-change-without-indexname-replaces-and-deletes-original"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3vectors"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_STACK_CAP_S = 300.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: S3 Vectors' refusal of an index that no longer exists.
_INDEX_NOT_FOUND = ("NotFoundException", "The specified index could not be found")

#: SSE-S3: an index declared without EncryptionConfiguration takes its bucket's default.
_DEFAULT_ENCRYPTION = {"sseType": "AES256"}


def _template(bucket_name: str, dimension: int) -> str:
    """One AWS::S3Vectors::Index, VectorBucketName set, IndexName omitted, UpdateReplacePolicy unset."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Index": {
                    "Type": "AWS::S3Vectors::Index",
                    "Properties": {
                        "VectorBucketName": bucket_name,
                        "DataType": "float32",
                        "Dimension": dimension,
                        "DistanceMetric": "cosine",
                    },
                },
            },
            "Outputs": {
                "IndexRef": {"Value": {"Ref": "Index"}},
                "IndexArn": {"Value": {"Fn::GetAtt": ["Index", "IndexArn"]}},
            },
        }
    )


def wait_stack(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in _TERMINAL:
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def expect_status(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return list(reversed(out))


def rows_since(cfn, stack_id: str, seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events(cfn, stack_id)
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def physical_ids(cfn, stack_id: str) -> dict[str, str]:
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def delete_stack(ctx, cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    expect_status(cfn, wait_stack(ctx, cfn, stack_id), "DELETE_COMPLETE")


def teardown_stack(cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = wait_stack(None, cfn, stack["StackId"])
    delete_stack(None, cfn, stack["StackId"])


def wait_error(ctx, fn, code: str, what: str) -> tuple:
    """Poll ``fn`` until it raises *code* (a delete can lag); return (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _budget_s(ctx, cap_s: float) -> float:
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _assert_index(s3v, arn: str, bucket: str, dimension: int) -> None:
    """GetIndex by ARN reports the templated properties exactly."""
    got = s3v.get_index(indexArn=arn)["index"]
    fields = (
        "vectorBucketName", "indexArn", "dataType", "dimension",
        "distanceMetric", "encryptionConfiguration",
    )
    seen = {k: got.get(k) for k in fields}
    want = {
        "vectorBucketName": bucket,
        "indexArn": arn,
        "dataType": "float32",
        "dimension": dimension,
        "distanceMetric": "cosine",
        "encryptionConfiguration": _DEFAULT_ENCRYPTION,
    }
    assert seen == want, f"GetIndex {arn}: {got!r}, expected {want!r}"
    assert arn.endswith(f"/index/{got['indexName']}"), (
        f"GetIndex indexName {got['indexName']!r} does not match its own ARN {arn!r}"
    )


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation S3 Vectors index with IndexName omitted is replaced when only Dimension
    changes: Ref/GetAtt point at a new, empty index ARN at the new dimension, and the original
    index is deleted (DELETE_COMPLETE, not DELETE_SKIPPED) so GetIndex on it then 404s.
    """
    cfn = ctx.client("cloudformation")
    s3v = ctx.client("s3vectors")
    bucket = ctx.unique_name("sim2real-cfnvid-")
    stack_name = ctx.unique_name("sim2real-cfnvid-stack-")

    s3v.create_vector_bucket(vectorBucketName=bucket)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    ref = {"stack": stack_name}
    ctx.on_cleanup(lambda: teardown_stack(cfn, ref))

    # ---- 1. create with Dimension 2, IndexName omitted: CloudFormation generates the name
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(bucket, 2), Tags=_TAGS
    )["StackId"]
    stack = wait_stack(ctx, cfn, ref["stack"])
    expect_status(cfn, stack, "CREATE_COMPLETE")
    first_arn = outputs(stack)["IndexRef"]
    assert outputs(stack) == {"IndexRef": first_arn, "IndexArn": first_arn}, (
        f"Ref and GetAtt outputs {outputs(stack)!r}"
    )
    assert physical_ids(cfn, ref["stack"]) == {"Index": first_arn}, (
        f"physical ids {physical_ids(cfn, ref['stack'])!r}"
    )
    _assert_index(s3v, first_arn, bucket, 2)
    s3v.put_vectors(
        indexArn=first_arn, vectors=[{"key": "v1", "data": {"float32": [1.0, 0.0]}}]
    )
    assert len(s3v.list_vectors(indexArn=first_arn)["vectors"]) == 1, (
        "the original index must hold the vector written to it before the replacement"
    )

    # ---- 2. update only Dimension, IndexName still omitted: a replacement, default policy Delete
    seen = {e["EventId"] for e in events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(bucket, 3), Tags=_TAGS)
    stack = wait_stack(ctx, cfn, ref["stack"])
    expect_status(cfn, stack, "UPDATE_COMPLETE")
    second_arn = outputs(stack)["IndexRef"]
    assert outputs(stack) == {"IndexRef": second_arn, "IndexArn": second_arn}, (
        f"Ref and GetAtt outputs after the update {outputs(stack)!r}"
    )
    assert second_arn != first_arn, "a Dimension change must mint a new index ARN"
    assert physical_ids(cfn, ref["stack"]) == {"Index": second_arn}, (
        f"physical ids after the update {physical_ids(cfn, ref['stack'])!r}"
    )

    rows = rows_since(cfn, ref["stack"], seen, "Index")
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"Index must announce its replacement, its events were {rows!r}"
    completed = [(s, pid) for s, _, pid in rows if s == "UPDATE_COMPLETE"]
    assert completed == [("UPDATE_COMPLETE", second_arn)], (
        f"Index must complete its update as the new physical id {second_arn!r}, events: {rows!r}"
    )
    deleted = [(s, pid) for s, _, pid in rows if s.startswith("DELETE_")]
    assert deleted == [("DELETE_IN_PROGRESS", first_arn), ("DELETE_COMPLETE", first_arn)], (
        f"with no UpdateReplacePolicy the replaced {first_arn!r} must be deleted (not retained), "
        f"the delete events of Index were {deleted!r}"
    )

    # ---- 3. the new index functions and starts empty; the original is gone, not just renamed
    _assert_index(s3v, second_arn, bucket, 3)
    assert s3v.list_vectors(indexArn=second_arn)["vectors"] == [], (
        "the replacement index must start with no vectors"
    )
    s3v.put_vectors(
        indexArn=second_arn, vectors=[{"key": "v2", "data": {"float32": [0.0, 1.0, 0.0]}}]
    )
    assert len(s3v.list_vectors(indexArn=second_arn)["vectors"]) == 1, (
        "the replacement index must accept and store a vector of its new dimension"
    )
    got = wait_error(ctx, lambda: s3v.get_index(indexArn=first_arn), _INDEX_NOT_FOUND[0], "index")
    assert got == _INDEX_NOT_FOUND, f"GetIndex on the deleted original answered {got!r}"
    listed = [i["indexName"] for i in s3v.list_indexes(vectorBucketName=bucket)["indexes"]]
    assert listed == [second_arn.rsplit("/", 1)[-1]], (
        f"ListIndexes after the replacement returned {listed!r}, expected only the new index"
    )

    # ---- 4. delete the stack; the externally created bucket outlives it
    delete_stack(ctx, cfn, ref["stack"])
    got = wait_error(
        ctx, lambda: s3v.get_index(indexArn=second_arn), _INDEX_NOT_FOUND[0], "index"
    )
    assert got == _INDEX_NOT_FOUND, f"GetIndex after the stack delete answered {got!r}"
    still = s3v.get_vector_bucket(vectorBucketName=bucket)["vectorBucket"]
    assert still["vectorBucketName"] == bucket, (
        f"the bucket created outside the stack must survive the stack delete, got {still!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
