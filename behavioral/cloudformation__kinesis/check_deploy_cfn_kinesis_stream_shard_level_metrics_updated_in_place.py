"""deploy-cfn-kinesis-stream-shard-level-metrics-updated-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-kinesis-stream-shard-level-metrics-updated-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "kinesis"]

_NOT_FOUND = "ResourceNotFoundException"
_STACK_CAP_S = 600.0
_METRICS_CAP_S = 120.0
_POLL_S = 2.0

_FIRST_SET = ["IncomingBytes", "OutgoingRecords"]
_SECOND_SET = ["IncomingBytes", "IteratorAgeMilliseconds", "WriteProvisionedThroughputExceeded"]


def _template(name: str, metrics: list[str] | None) -> str:
    properties = {"Name": name, "ShardCount": 1}
    if metrics is not None:
        properties["DesiredShardLevelMetrics"] = metrics
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Stream": {"Type": "AWS::Kinesis::Stream", "Properties": properties}},
        }
    )


def _settle(cfn, stack_id: str, deadline: float) -> dict:
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {stack['StackStatus']!r}")
        time.sleep(_POLL_S)


def _require(cfn, stack_id: str, want: str) -> dict:
    stack = _settle(cfn, stack_id, time.monotonic() + _STACK_CAP_S)
    if stack["StackStatus"] != want:
        raise AssertionError(f"stack {stack_id} ended {stack['StackStatus']!r}, expected {want!r}")
    return stack


def _refused(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, call returned {result!r} instead")


def _active_metrics(kinesis, name: str) -> set[str]:
    """The union of ShardLevelMetrics across every EnhancedMonitoring entry of the stream."""
    summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["StreamStatus"] == "ACTIVE", f"stream {name} was {summary['StreamStatus']!r}"
    found: set[str] = set()
    for entry in summary["EnhancedMonitoring"]:
        found.update(entry.get("ShardLevelMetrics", []))
    return found


def _wait_metrics(kinesis, name: str, want: set[str]) -> None:
    """Poll DescribeStreamSummary until its enhanced-monitoring set equals ``want`` exactly."""
    deadline = time.monotonic() + _METRICS_CAP_S
    while True:
        found = _active_metrics(kinesis, name)
        if found == want:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"stream {name} reported {found!r}, expected {want!r}")
        time.sleep(_POLL_S)


@tags(
    "axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation",
    "dp:api", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """A stream's DesiredShardLevelMetrics changes in place through CloudFormation, and removing
    the property from the template leaves Kinesis's own enhanced-monitoring state exactly as the
    last applied value, rather than clearing it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesis-stream.html
    """
    cfn = ctx.client("cloudformation")
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-cfnkinmon-")
    stack = ctx.unique_name("sim2real-cfnkinmon-stack-")
    created: dict = {}

    ctx.on_cleanup(lambda: _delete(cfn, created))
    created["id"] = cfn.create_stack(
        StackName=stack, TemplateBody=_template(name, _FIRST_SET),
        Tags=[{"Key": "sim2real", "Value": stack}],
    )["StackId"]
    _require(cfn, created["id"], "CREATE_COMPLETE")
    _wait_metrics(kinesis, name, set(_FIRST_SET))

    # ---- in-place: a different metric set, the same physical stream
    cfn.update_stack(StackName=created["id"], TemplateBody=_template(name, _SECOND_SET))
    _require(cfn, created["id"], "UPDATE_COMPLETE")
    resources = cfn.describe_stack_resources(StackName=created["id"])["StackResources"]
    (stream_resource,) = [r for r in resources if r["LogicalResourceId"] == "Stream"]
    assert stream_resource["PhysicalResourceId"] == name, (
        f"changing DesiredShardLevelMetrics replaced the stream, physical id became "
        f"{stream_resource['PhysicalResourceId']!r}"
    )
    _wait_metrics(kinesis, name, set(_SECOND_SET))

    # ---- in-place: dropping the property leaves the last-applied metrics in effect
    cfn.update_stack(StackName=created["id"], TemplateBody=_template(name, None))
    _require(cfn, created["id"], "UPDATE_COMPLETE")
    resources = cfn.describe_stack_resources(StackName=created["id"])["StackResources"]
    (stream_resource,) = [r for r in resources if r["LogicalResourceId"] == "Stream"]
    assert stream_resource["PhysicalResourceId"] == name, (
        f"dropping DesiredShardLevelMetrics replaced the stream, physical id became "
        f"{stream_resource['PhysicalResourceId']!r}"
    )
    for _ in range(3):
        assert _active_metrics(kinesis, name) == set(_SECOND_SET), (
            "removing the property from the template must not disable the metrics it last set"
        )
        time.sleep(_POLL_S)

    # ---- delete: the stream is gone regardless of its last monitoring state
    cfn.delete_stack(StackName=created["id"])
    _require(cfn, created["id"], "DELETE_COMPLETE")
    got = _refused(lambda: kinesis.describe_stream_summary(StreamName=name))
    want = (_NOT_FOUND, f"Stream {name} under account {ctx.account} not found.")
    assert got == want, f"DescribeStreamSummary after delete answered {got!r}, expected {want!r}"


def _delete(cfn, created: dict) -> None:
    stack_id = created.get("id")
    if stack_id is None:
        return
    try:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in exc.response["Error"].get("Message", ""):
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS"):
        _settle(cfn, stack_id, time.monotonic() + _STACK_CAP_S)
    cfn.delete_stack(StackName=stack_id)
    final = _settle(cfn, stack_id, time.monotonic() + _STACK_CAP_S)
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise AssertionError(f"teardown of {stack_id} ended {final['StackStatus']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
