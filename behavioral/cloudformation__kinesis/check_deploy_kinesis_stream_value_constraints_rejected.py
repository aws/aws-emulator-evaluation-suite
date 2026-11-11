"""deploy-kinesis-stream-value-constraints-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-kinesis-stream-value-constraints-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "kinesis"]

_STACK_REASON_TEMPLATE = (
    "Validation failed with {n} error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _template(stream_name: str, *, retention_hours: int, distribution_strategy: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Stream": {
                "Type": "AWS::Kinesis::Stream",
                "Properties": {
                    "Name": stream_name,
                    "RetentionPeriodHours": retention_hours,
                    "RecordDistributionStrategy": distribution_strategy,
                    "StreamModeDetails": {"StreamMode": "ON_DEMAND"},
                },
            },
        },
    })


def _validation_errors(cfn, stack_name: str) -> list[tuple]:
    """``(logical id, type, name, status, mode, reason, path)`` of each VALIDATION_ERROR event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend((e.get("LogicalResourceId"), e.get("ResourceType"), e.get("ValidationName"),
                    e.get("ValidationStatus"), e.get("ValidationFailureMode"), e.get("ValidationStatusReason"),
                    e.get("ValidationPath"))
                   for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR")
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A Kinesis stream's RetentionPeriodHours below its minimum and RecordDistributionStrategy
    outside its enum both fail CFN's property-value validation before provisioning; the
    boundary values deploy and Kinesis reads back the same values."""
    cfn = ctx.client("cloudformation")
    kin = ctx.client("kinesis")

    bad_stack = ctx.unique_name("sim2real-cfn-kinval-bad-")
    bad_stream = ctx.unique_name("sim2real-kinval-bad-")
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bad_stream, retention_hours=1, distribution_strategy="BOGUS"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))

    status = _wait_terminal(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", f"expected the bad values to roll back, ended in {status!r}"

    events = [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=bad_stack)
              for e in page["StackEvents"]]
    stack_failed = [e.get("ResourceStatusReason") for e in events
                    if e["LogicalResourceId"] == bad_stack and e["ResourceStatus"] == "CREATE_FAILED"]
    want_reason = _STACK_REASON_TEMPLATE.format(n=2)
    assert stack_failed == [want_reason], (
        f"the stack's CREATE_FAILED reasons were {stack_failed!r}, expected [{want_reason!r}]"
    )
    found = sorted(_validation_errors(cfn, bad_stack))
    want = sorted([
        ("Stream", "AWS::Kinesis::Stream", "PROPERTY_VALIDATION", "FAILED", "FAIL",
         "#/RetentionPeriodHours: 1 is not greater or equal to 24",
         "/Resources/Stream/Properties/RetentionPeriodHours"),
        ("Stream", "AWS::Kinesis::Stream", "PROPERTY_VALIDATION", "FAILED", "FAIL",
         "BOGUS is not a valid enum value. Supported values: [AUTO, USER_PARTITION_KEY]",
         "/Resources/Stream/Properties/RecordDistributionStrategy"),
    ])
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
    assert resources == [], f"a stack rejected before provisioning reports resources {resources!r}"

    code, message = _error(lambda: kin.describe_stream_summary(StreamName=bad_stream))
    assert (code, message) == (
        "ResourceNotFoundException", f"Stream {bad_stream} under account {ctx.account} not found.",
    ), f"the never-provisioned stream's DescribeStreamSummary answered {(code, message)!r}"

    _delete_stack(cfn, bad_stack)
    code, message = _error(lambda: cfn.describe_stacks(StackName=bad_stack))
    assert (code, message) == ("ValidationError", f"Stack with id {bad_stack} does not exist"), (
        f"DescribeStacks of the deleted rolled-back stack answered {(code, message)!r}"
    )

    # Positive control: the boundary values (minimum retention, a listed enum value) deploy,
    # and Kinesis's own DescribeStreamSummary reads back the same values.
    good_stack = ctx.unique_name("sim2real-cfn-kinval-good-")
    good_stream = ctx.unique_name("sim2real-kinval-good-")
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_stream, retention_hours=24, distribution_strategy="AUTO"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"the control stack settled at {status!r}, expected CREATE_COMPLETE"

    summary = kin.describe_stream_summary(StreamName=good_stream)["StreamDescriptionSummary"]
    retention_distribution = (summary.get("RetentionPeriodHours"), summary.get("RecordDistributionStrategy"))
    assert retention_distribution == (24, "AUTO"), (
        f"expected (RetentionPeriodHours, RecordDistributionStrategy) at their boundary (24, 'AUTO'), "
        f"got {retention_distribution!r}"
    )

    _delete_stack(cfn, good_stack)
    code, message = _error(lambda: kin.describe_stream_summary(StreamName=good_stream))
    assert (code, message) == (
        "ResourceNotFoundException", f"Stream {good_stream} under account {ctx.account} not found.",
    ), f"the deleted control stream's DescribeStreamSummary answered {(code, message)!r}"


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 300.0) -> str:
    """Poll DescribeStacks every 2s until the stack settles; return the terminal status."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last.endswith("_COMPLETE") or last.endswith("_FAILED"):
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} never settled within {timeout_s}s (last={last!r})")


def _delete_stack(cfn, stack_name: str, timeout_s: float = 300.0) -> None:
    """Delete the stack and wait for it to vanish; DELETE_FAILED or the deadline raises."""
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        if not stacks:
            return
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} not deleted within {timeout_s}s (last status {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
