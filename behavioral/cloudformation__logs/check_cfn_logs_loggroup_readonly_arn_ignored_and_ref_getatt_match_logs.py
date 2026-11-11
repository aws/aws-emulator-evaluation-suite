"""cfn-logs-loggroup-readonly-arn-ignored-and-ref-getatt-match-logs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-loggroup-readonly-arn-ignored-and-ref-getatt-match-logs"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

_FAKE_ACCOUNT = "111122223333"

_STACK_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                   "DELETE_COMPLETE", "DELETE_FAILED"}


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(cfn, stack_id)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}


def _describe_group(logs, name: str) -> dict | None:
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page["logGroups"]:
            if g["logGroupName"] == name:
                return g
    return None


def _error(fn) -> dict:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(group_name: str, bogus_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": group_name,
                    "RetentionInDays": 14,
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                    # This type's only readOnlyProperty, set to a value AWS never minted.
                    "Arn": bogus_arn,
                },
            },
        },
        "Outputs": {
            "GroupRef": {"Value": {"Ref": "Group"}},
            "GroupArnAttr": {"Value": {"Fn::GetAtt": ["Group", "Arn"]}},
        },
    })


@tags(
    "axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A template that sets AWS::Logs::LogGroup's readOnlyProperty Arn deploys as if it were
    absent: the group gets its documented ARN, Ref and Fn::GetAtt Arn equal the Logs API's own
    answer, and RetentionInDays and Tags read back from Logs."""
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    group_name = ctx.unique_name("sim2real-behav-cfnro-lg-")
    stack_name = ctx.unique_name("sim2real-behav-cfnro-lg-stk-")
    bogus_arn = f"arn:aws:logs:{ctx.region}:{_FAKE_ACCOUNT}:log-group:not-the-real-group:*"
    group_arn = f"arn:aws:logs:{ctx.region}:{ctx.account}:log-group:{group_name}"

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(group_name, bogus_arn),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"a readOnlyProperty value in the template must not block the create; got {status!r}")

    described = _describe_group(logs, group_name)
    assert described is not None, f"DescribeLogGroups does not show {group_name!r} after CREATE_COMPLETE"
    assert described["arn"] == f"{group_arn}:*", (
        f"the Logs API's arn is not the documented log-group ARN of {group_name!r}: "
        f"{described['arn']!r}")
    assert described.get("retentionInDays") == 14, (
        f"RetentionInDays 14 did not reach Logs: {described.get('retentionInDays')!r}")
    group_tags = logs.list_tags_for_resource(resourceArn=group_arn)["tags"]
    own_tags = {k: v for k, v in group_tags.items() if not k.startswith("aws:")}
    assert own_tags == {"sim2real": CHECK}, f"the group's Tags read back as {own_tags!r}"

    outputs = _outputs(cfn, stack_id)
    assert outputs["GroupRef"] == group_name, (
        f"Ref must equal the log group name {group_name!r}; got {outputs['GroupRef']!r}")
    assert outputs["GroupArnAttr"] == described["arn"], (
        f"GetAtt Arn must equal the Logs API's own arn {described['arn']!r}; got "
        f"{outputs['GroupArnAttr']!r}")

    _delete_stack_and_wait(cfn, stack_id)
    assert _describe_group(logs, group_name) is None, f"log group {group_name!r} survived its stack delete"
    err = _error(lambda: logs.put_log_events(
        logGroupName=group_name, logStreamName="sim2real-any-stream",
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "should not be accepted"}]))
    assert err["Code"] == "ResourceNotFoundException", (
        f"writing to the deleted log group returned {err['Code']!r}, expected ResourceNotFoundException")
    assert err["Message"] == "The specified log group does not exist.", (
        f"expected the standard not-found message, got {err['Message']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
