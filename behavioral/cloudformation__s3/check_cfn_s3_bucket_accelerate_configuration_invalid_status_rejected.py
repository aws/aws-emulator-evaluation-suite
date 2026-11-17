"""cfn-s3-bucket-accelerate-configuration-invalid-status-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3-bucket-accelerate-configuration-invalid-status-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_TERMINAL = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}
_VALIDATION_REASON = "Disabled is not a valid enum value. Supported values: [Enabled, Suspended]"
_VALIDATION_PATH = "/Resources/B/Properties/AccelerateConfiguration/AccelerationStatus"
_NOT_FOUND = ("404", "Not Found")


def _template(bucket: str, status: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "B": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": bucket,
                        "AccelerateConfiguration": {"AccelerationStatus": status},
                    },
                },
            },
        }
    )


def _wait_terminal(cfn, name: str, timeout_s: float = 300.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(2.0)
    raise AssertionError(f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _validation_errors(cfn, name: str) -> list[tuple]:
    """``(logical id, reason, path)`` of each VALIDATION_ERROR operation event for B."""
    out: list[tuple] = []
    kwargs = {"StackName": name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("LogicalResourceId"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"]
            if e.get("EventType") == "VALIDATION_ERROR" and e.get("LogicalResourceId") == "B"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, name: str) -> None:
    cfn.delete_stack(StackName=name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A bucket's AccelerateConfiguration naming a status outside Enabled/Suspended fails
    CloudFormation's pre-provisioning enum check with its exact message and creates nothing,
    while a declared Enabled status deploys and reads back through the bucket's own API.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stack_tags = [{"Key": "sim2real", "Value": CHECK}]

    # --- positive control: a valid status deploys and reads back -----------------------------
    good_bucket = ctx.unique_name("sim2real-cfn-accelst-ok-")
    good_stack = ctx.unique_name("sim2real-cfn-accelst-ok-")
    cfn.create_stack(
        StackName=good_stack, TemplateBody=_template(good_bucket, "Enabled"), Tags=stack_tags
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    got = s3.get_bucket_accelerate_configuration(Bucket=good_bucket).get("Status")
    assert got == "Enabled", f"control bucket must read back Enabled, got {got!r}"

    # --- negative: a status outside the closed enum ------------------------------------------
    bad_bucket = ctx.unique_name("sim2real-cfn-accelst-bad-")
    bad_stack = ctx.unique_name("sim2real-cfn-accelst-bad-")
    cfn.create_stack(
        StackName=bad_stack, TemplateBody=_template(bad_bucket, "Disabled"), Tags=stack_tags
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    status = _wait_terminal(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", f"invalid status: expected ROLLBACK_COMPLETE, got {status!r}"
    found = _validation_errors(cfn, bad_stack)
    assert found == [("B", _VALIDATION_REASON, _VALIDATION_PATH)], (
        f"invalid status: validation errors expected a single ({_VALIDATION_REASON!r}, "
        f"{_VALIDATION_PATH!r}), got {found!r}"
    )
    resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
    logical_ids = sorted(r["LogicalResourceId"] for r in resources)
    assert logical_ids == [], (
        f"invalid status: a stack rejected before provisioning must list no resources, got {logical_ids!r}"
    )
    code, message = _error(lambda: s3.head_bucket(Bucket=bad_bucket))
    assert (code, message) == _NOT_FOUND, (
        f"invalid status: expected the bucket to never exist {_NOT_FOUND!r}, got {code!r}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
