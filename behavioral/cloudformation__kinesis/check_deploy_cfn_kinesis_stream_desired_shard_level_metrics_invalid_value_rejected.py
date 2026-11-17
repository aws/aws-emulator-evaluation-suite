"""deploy-cfn-kinesis-stream-desired-shard-level-metrics-invalid-value-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-kinesis-stream-desired-shard-level-metrics-invalid-value-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "kinesis"]

_NOT_FOUND = "ResourceNotFoundException"
_STACK_CAP_S = 300.0
_POLL_S = 2.0


def _template(name: str, metrics: list) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Stream": {
                    "Type": "AWS::Kinesis::Stream",
                    "Properties": {
                        "Name": name, "ShardCount": 1, "DesiredShardLevelMetrics": metrics,
                    },
                },
            },
        }
    )


def _terminal(cfn, stack_name: str) -> str:
    """The settled StackStatus; DescribeStacks-by-name can drop a stack the instant it deletes."""
    deadline = time.monotonic() + _STACK_CAP_S
    while True:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Message"] == f"Stack with id {stack_name} does not exist":
                return "DELETE_COMPLETE"
            raise
        if not status.endswith("_IN_PROGRESS"):
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} still {status!r}")
        time.sleep(_POLL_S)


def _validation_errors(cfn, stack_name: str) -> list:
    """(resource type, reason, path) of every VALIDATION_ERROR describe_events reports."""
    out = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("ResourceType"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR"
        )
        token = page.get("NextToken")
        if not token:
            return out
        kwargs["NextToken"] = token


def _refused(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, call returned {result!r} instead")


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    status = _terminal(cfn, stack_name)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"deleting {stack_name} ended {status!r}")


def _teardown_stack(cfn, stack_name: str) -> None:
    """The cleanup net: a stack the run already deleted is nothing to do, any other state deletes."""
    try:
        cfn.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack_name} does not exist":
            return
        raise
    _delete_stack(cfn, stack_name)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DesiredShardLevelMetrics entry outside Kinesis's metric enum fails CloudFormation's
    property validation before any stream provisions; a listed metric name provisions and
    Kinesis reads back the same value.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesis-stream.html
    """
    cfn = ctx.client("cloudformation")
    kinesis = ctx.client("kinesis")

    bad_stack = ctx.unique_name("sim2real-cfn-kinmonval-bad-")
    bad_name = ctx.unique_name("sim2real-kinmonval-bad-")
    cfn.create_stack(
        StackName=bad_stack, TemplateBody=_template(bad_name, ["BOGUS"]),
        Tags=[{"Key": "sim2real", "Value": bad_stack}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(cfn, bad_stack))
    status = _terminal(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", f"the bad metric name ended {status!r}, expected rollback"

    found = _validation_errors(cfn, bad_stack)
    want = [(
        "AWS::Kinesis::Stream",
        "BOGUS is not a valid enum value. Supported values: [IncomingBytes, IncomingRecords, "
        "OutgoingBytes, OutgoingRecords, WriteProvisionedThroughputExceeded, "
        "ReadProvisionedThroughputExceeded, IteratorAgeMilliseconds, ALL]",
        "/Resources/Stream/Properties/DesiredShardLevelMetrics/0",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
    assert resources == [], f"a stack rejected before provisioning reports resources {resources!r}"
    code, message = _refused(lambda: kinesis.describe_stream_summary(StreamName=bad_name))
    want_error = (_NOT_FOUND, f"Stream {bad_name} under account {ctx.account} not found.")
    assert (code, message) == want_error, (
        f"the never-provisioned stream's DescribeStreamSummary answered {(code, message)!r}"
    )

    # Positive control: a metric the enum lists provisions, and Kinesis echoes it back.
    good_stack = ctx.unique_name("sim2real-cfn-kinmonval-good-")
    good_name = ctx.unique_name("sim2real-kinmonval-good-")
    cfn.create_stack(
        StackName=good_stack, TemplateBody=_template(good_name, ["IncomingBytes"]),
        Tags=[{"Key": "sim2real", "Value": good_stack}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(cfn, good_stack))
    status = _terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"the control stack settled at {status!r}"

    summary = kinesis.describe_stream_summary(StreamName=good_name)["StreamDescriptionSummary"]
    live = {m for entry in summary["EnhancedMonitoring"] for m in entry.get("ShardLevelMetrics", [])}
    assert live == {"IncomingBytes"}, f"the control stream's enhanced monitoring reads back {live!r}"

    _delete_stack(cfn, good_stack)
    code, message = _refused(lambda: kinesis.describe_stream_summary(StreamName=good_name))
    assert (code, message) == (
        _NOT_FOUND, f"Stream {good_name} under account {ctx.account} not found.",
    ), f"the deleted control stream's DescribeStreamSummary answered {(code, message)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
