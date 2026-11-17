"""cfn-s3vectors-index-createonly-change-replaces-unnamed-conflicts-named."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3vectors-index-createonly-change-replaces-unnamed-conflicts-named"
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

#: S3 Vectors' refusal of an index that no longer exists.
_INDEX_NOT_FOUND = ("NotFoundException", "The specified index could not be found")


def _rename_reason(arn: str) -> str:
    """CloudFormation's own guard against replacing a resource whose name the template fixed."""
    return (
        "CloudFormation cannot update a stack when a custom-named resource requires "
        f"replacing. Rename {arn} and update the stack again."
    )


def _template(bucket: str, dimension: int, distance_metric: str, index_name: str | None) -> str:
    """One AWS::S3Vectors::Index; IndexName is set only when *index_name* is given."""
    props = {
        "VectorBucketName": bucket,
        "DataType": "float32",
        "Dimension": dimension,
        "DistanceMetric": distance_metric,
    }
    if index_name is not None:
        props["IndexName"] = index_name
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Index": {"Type": "AWS::S3Vectors::Index", "Properties": props}},
            "Outputs": {
                "IndexRef": {"Value": {"Ref": "Index"}},
                "IndexArn": {"Value": {"Fn::GetAtt": ["Index", "IndexArn"]}},
            },
        }
    )


def wait_stack(cfn, stack_id: str, timeout_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until it leaves every ``*_IN_PROGRESS`` status."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in _TERMINAL:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s:.0f}s"
            )
        time.sleep(_POLL_S)


def events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return list(reversed(out))


def outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def physical_ids(cfn, stack_id: str) -> dict[str, str]:
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def failed_reason(evts: list[dict], logical_id: str, status: str) -> str:
    """The single ``ResourceStatusReason`` of *logical_id*'s one *status* row among *evts*."""
    rows = [
        e.get("ResourceStatusReason") for e in evts
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def delete_stack(cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    stack = wait_stack(cfn, stack_id)
    assert stack["StackStatus"] == "DELETE_COMPLETE", (
        f"stack {stack_id} delete ended {stack['StackStatus']!r}"
    )


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
        stack = wait_stack(cfn, stack["StackId"])
    delete_stack(cfn, stack["StackId"])


def wait_not_found(fn, code: str) -> tuple:
    """Poll *fn* until it raises *code* (a delete can lag); return ``(Code, Message)``."""
    deadline = time.monotonic() + _GONE_CAP_S
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
            raise AssertionError(f"still answered after {_GONE_CAP_S:.0f}s: {last!r}")
        time.sleep(_POLL_S)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A create-only property change on an S3 Vectors index replaces cleanly when CloudFormation
    mints the index name, but CloudFormation refuses the same change and rolls the stack back
    when the template names the index explicitly, since the name cannot carry to a replacement.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html
    """
    cfn = ctx.client("cloudformation")
    s3v = ctx.client("s3vectors")
    bucket = ctx.unique_name("sim2real-cfnidxrep-")
    bucket_tags = [{"Key": "sim2real", "Value": bucket}]

    s3v.create_vector_bucket(vectorBucketName=bucket)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    # ---- A: IndexName omitted, so CloudFormation mints a fresh physical name on replacement.
    stack_a_name = ctx.unique_name("sim2real-cfnidxrep-a-")
    ref_a = {"stack": stack_a_name}
    ctx.on_cleanup(lambda: teardown_stack(cfn, ref_a))
    ref_a["stack"] = cfn.create_stack(
        StackName=stack_a_name,
        TemplateBody=_template(bucket, 2, "cosine", None),
        Tags=bucket_tags,
    )["StackId"]
    stack_a = wait_stack(cfn, ref_a["stack"])
    assert stack_a["StackStatus"] == "CREATE_COMPLETE", (
        f"stack A ended {stack_a['StackStatus']!r}, expected CREATE_COMPLETE"
    )
    arn_a1 = outputs(stack_a)["IndexRef"]
    assert outputs(stack_a) == {"IndexRef": arn_a1, "IndexArn": arn_a1}, (
        f"stack A outputs {outputs(stack_a)!r}"
    )
    first = s3v.get_index(indexArn=arn_a1)["index"]
    assert first["distanceMetric"] == "cosine", f"stack A's first index {first!r}"

    cfn.update_stack(
        StackName=ref_a["stack"],
        TemplateBody=_template(bucket, 2, "euclidean", None),
        Tags=bucket_tags,
    )
    stack_a = wait_stack(cfn, ref_a["stack"])
    assert stack_a["StackStatus"] == "UPDATE_COMPLETE", (
        f"stack A's DistanceMetric update ended {stack_a['StackStatus']!r}, expected UPDATE_COMPLETE"
    )
    arn_a2 = outputs(stack_a)["IndexRef"]
    assert arn_a2 != arn_a1, "a DistanceMetric change with IndexName omitted must mint a new ARN"
    assert outputs(stack_a) == {"IndexRef": arn_a2, "IndexArn": arn_a2}, (
        f"stack A outputs after the update {outputs(stack_a)!r}"
    )
    second = s3v.get_index(indexArn=arn_a2)["index"]
    assert second["distanceMetric"] == "euclidean", f"stack A's replacement index {second!r}"
    got = wait_not_found(lambda: s3v.get_index(indexArn=arn_a1), _INDEX_NOT_FOUND[0])
    assert got == _INDEX_NOT_FOUND, f"GetIndex on stack A's deleted original answered {got!r}"

    # ---- B: IndexName explicit, so the replacement would share the still-live original's name.
    index_name_b = ctx.unique_name("sim2real-cfnidxrep-b-")
    stack_b_name = ctx.unique_name("sim2real-cfnidxrep-bs-")
    ref_b = {"stack": stack_b_name}
    ctx.on_cleanup(lambda: teardown_stack(cfn, ref_b))
    ref_b["stack"] = cfn.create_stack(
        StackName=stack_b_name,
        TemplateBody=_template(bucket, 3, "cosine", index_name_b),
        Tags=bucket_tags,
    )["StackId"]
    stack_b = wait_stack(cfn, ref_b["stack"])
    assert stack_b["StackStatus"] == "CREATE_COMPLETE", (
        f"stack B ended {stack_b['StackStatus']!r}, expected CREATE_COMPLETE"
    )
    arn_b = outputs(stack_b)["IndexRef"]
    original = s3v.get_index(indexArn=arn_b)["index"]
    assert original["dimension"] == 3, f"stack B's original index {original!r}"

    seen = {e["EventId"] for e in events(cfn, ref_b["stack"])}
    cfn.update_stack(
        StackName=ref_b["stack"],
        TemplateBody=_template(bucket, 4, "cosine", index_name_b),
        Tags=bucket_tags,
    )
    stack_b = wait_stack(cfn, ref_b["stack"])
    assert stack_b["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"stack B's Dimension update ended {stack_b['StackStatus']!r}, expected "
        f"UPDATE_ROLLBACK_COMPLETE"
    )
    new_rows = [e for e in events(cfn, ref_b["stack"]) if e["EventId"] not in seen]
    reason = failed_reason(new_rows, "Index", "UPDATE_FAILED")
    want_reason = _rename_reason(arn_b)
    assert reason == want_reason, f"stack B's Index UPDATE_FAILED reason {reason!r}, expected {want_reason!r}"

    # ---- the original index is untouched by its rejected, same-named replacement attempt
    assert physical_ids(cfn, ref_b["stack"]) == {"Index": arn_b}, (
        f"stack B physical ids after the rollback {physical_ids(cfn, ref_b['stack'])!r}"
    )
    still = s3v.get_index(indexArn=arn_b)["index"]
    assert still["dimension"] == 3, f"stack B's original index after the rollback {still!r}"
    listed = [
        i["indexName"] for i in s3v.list_indexes(vectorBucketName=bucket)["indexes"]
        if i["indexName"] == index_name_b
    ]
    assert listed == [index_name_b], (
        f"ListIndexes by name {index_name_b!r} returned {listed!r}, expected exactly one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
