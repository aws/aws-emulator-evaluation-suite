"""cfn-s3vectors-index-dimension-above-maximum-create-rejected-sibling-stack-unaffected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3vectors-index-dimension-above-maximum-create-rejected-sibling-stack-unaffected"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3vectors"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_STACK_CAP_S = 300.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: The documented ceiling (https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/
#: aws-resource-s3vectors-index.html): Dimension is 1..4096.
_MAX_DIMENSION = 4096
_OVER_MAX_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)


def _template(bucket_name: str, dimension: int) -> str:
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
            "Outputs": {"IndexArn": {"Value": {"Fn::GetAtt": ["Index", "IndexArn"]}}},
        }
    )


def wait_stack(cfn, stack_id: str, timeout_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
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
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return list(reversed(out))


def stack_reason(cfn, stack_id: str, status: str) -> str:
    """The ResourceStatusReason of the single stack-level event in *status*."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events(cfn, stack_id)
        if e["LogicalResourceId"] == e["StackName"] and e["ResourceStatus"] == status
    ]
    assert len(rows) == 1, f"expected one stack-level {status} event, got {rows!r}"
    return rows[0]


def resource_rows(cfn, stack_id: str, logical_id: str) -> list[tuple]:
    """(status, physical id) of every event for *logical_id*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("PhysicalResourceId"))
        for e in events(cfn, stack_id)
        if e["LogicalResourceId"] == logical_id
    ]


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


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation S3 Vectors index whose Dimension is set one past the documented 4096
    maximum fails stack creation before any Index resource is touched, while a sibling stack at
    the maximum creates, functions and is unaffected by the rejected stack.
    """
    cfn = ctx.client("cloudformation")
    s3v = ctx.client("s3vectors")
    bucket = ctx.unique_name("sim2real-cfnvidm-")
    good_name = ctx.unique_name("sim2real-cfnvidm-good-")
    bad_name = ctx.unique_name("sim2real-cfnvidm-bad-")

    s3v.create_vector_bucket(vectorBucketName=bucket)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    good_ref = {"stack": good_name}
    ctx.on_cleanup(lambda: teardown_stack(cfn, good_ref))
    bad_ref = {"stack": bad_name}
    ctx.on_cleanup(lambda: teardown_stack(cfn, bad_ref))

    # ---- positive control: creating at the documented maximum succeeds
    good_ref["stack"] = cfn.create_stack(
        StackName=good_name, TemplateBody=_template(bucket, _MAX_DIMENSION), Tags=_TAGS
    )["StackId"]
    good_stack = wait_stack(cfn, good_ref["stack"])
    assert good_stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the stack at the maximum Dimension ended {good_stack['StackStatus']!r}"
    )
    good_arn = {o["OutputKey"]: o["OutputValue"] for o in good_stack["Outputs"]}["IndexArn"]
    s3v.put_vectors(
        indexArn=good_arn, vectors=[{"key": "v1", "data": {"float32": [1.0] * _MAX_DIMENSION}}]
    )
    assert len(s3v.list_vectors(indexArn=good_arn)["vectors"]) == 1, (
        "the index at the maximum Dimension must accept and store a vector"
    )

    # ---- negative: raising Dimension one past the maximum is a stack-level validation failure
    bad_ref["stack"] = cfn.create_stack(
        StackName=bad_name, TemplateBody=_template(bucket, _MAX_DIMENSION + 1), Tags=_TAGS
    )["StackId"]
    bad_stack = wait_stack(cfn, bad_ref["stack"])
    assert bad_stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"the stack past the maximum Dimension ended {bad_stack['StackStatus']!r}, "
        f"expected ROLLBACK_COMPLETE"
    )
    reason = stack_reason(cfn, bad_ref["stack"], "CREATE_FAILED")
    assert reason == _OVER_MAX_REASON, f"CREATE_FAILED reason was {reason!r}"
    rows = resource_rows(cfn, bad_ref["stack"], "Index")
    assert rows == [], (
        f"a Dimension past the maximum must be caught before any Index resource is touched, "
        f"its events were {rows!r}"
    )

    # ---- the rejected stack's own index was never created
    listed = [i["indexName"] for i in s3v.list_indexes(vectorBucketName=bucket)["indexes"]]
    good_name_part = good_arn.rsplit("/", 1)[-1]
    assert listed == [good_name_part], (
        f"ListIndexes after the rejected stack returned {listed!r}, expected only the control index"
    )

    # ---- the control index and its vector are unaffected by the rejected sibling stack
    still = s3v.get_index(indexArn=good_arn)["index"]
    assert still["dimension"] == _MAX_DIMENSION, (
        f"the control index's dimension changed to {still['dimension']!r}"
    )
    assert len(s3v.list_vectors(indexArn=good_arn)["vectors"]) == 1, (
        "the control index's stored vector must survive the sibling stack's rollback"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
