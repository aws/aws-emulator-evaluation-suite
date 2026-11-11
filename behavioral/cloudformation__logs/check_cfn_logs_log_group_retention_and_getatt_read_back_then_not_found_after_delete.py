"""cfn-logs-log-group-retention-and-getatt-read-back-then-not-found-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-log-group-retention-and-getatt-read-back-then-not-found-after-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

_DEADLINE_S = 300.0


def _error(fn):
    """Call fn(), which AWS must refuse; return (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _teardown_stack(cfn, stack_id: str) -> None:
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _describe_group(logs, name: str) -> dict | None:
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page["logGroups"]:
            if g["logGroupName"] == name:
                return g
    return None


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-created AWS::Logs::LogGroup reads back its own properties and GetAtt ARN
    through the Logs API, and the stack delete removes it, read as a Logs not-found.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-cfn-lg-")
    stack = ctx.unique_name("sim2real-cfn-lg-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": group,
                    "RetentionInDays": 14,
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
        },
        "Outputs": {
            "GroupArnOut": {"Value": {"Fn::GetAtt": ["Group", "Arn"]}},
        },
    }

    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack} ended {status}: {_failures(cfn, stack_id)!r}"

    physical_id = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Group")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert physical_id == group, f"LogGroup physical id is {physical_id!r}, expected {group!r}"

    getatt_arn = {o["OutputKey"]: o["OutputValue"]
                  for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}["GroupArnOut"]

    described = _describe_group(logs, group)
    assert described is not None, f"DescribeLogGroups does not show {group!r} after CREATE_COMPLETE"
    assert described["retentionInDays"] == 14, (
        f"retentionInDays read back as {described['retentionInDays']!r}, expected 14")
    assert described["arn"] == getatt_arn, (
        f"Fn::GetAtt Arn {getatt_arn!r} does not match DescribeLogGroups arn {described['arn']!r}")

    _teardown_stack(cfn, stack_id)
    assert _describe_group(logs, group) is None, f"log group {group!r} survived its stack delete"
    code, message = _error(lambda: logs.put_log_events(
        logGroupName=group, logStreamName="sim2real-any-stream", logEvents=[
            {"timestamp": int(time.time() * 1000), "message": "should not be accepted"}]))
    assert code == "ResourceNotFoundException", (
        f"writing to the deleted log group returned {code!r}, expected ResourceNotFoundException")
    expected = "The specified log group does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
