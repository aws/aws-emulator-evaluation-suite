"""cfn-sns-topic-display-name-and-getatt-read-back-then-not-found-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sns-topic-display-name-and-getatt-read-back-then-not-found-after-delete"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "sns"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_id)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    """Poll DescribeStacks by stack id (resolves through DELETE_COMPLETE, unlike
    the bare name) until a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical_id:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical_id!r} in stack {stack_id!r}: {resources!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SNS::Topic is real at SNS: the DisplayName it
    declared and every Fn::GetAtt attribute it outputs match SNS's own answer, and
    deleting the stack removes the topic from SNS, not just from CFN."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    stack_name = ctx.unique_name("sim2real-behav-cfn-snst-")
    display_name = ctx.unique_name("sim2real-dn-")[:100]

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"DisplayName": display_name},
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "TopicName": {"Value": {"Fn::GetAtt": ["Topic", "TopicName"]}},
        },
    })

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    created = _wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {created!r}"

    topic_arn = _physical_id(cfn, stack_id, "Topic")

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    assert outputs["TopicArn"] == topic_arn, (
        f"Ref Topic was {outputs['TopicArn']!r}, DescribeStackResources physical id is {topic_arn!r}"
    )
    expected_name = topic_arn.rsplit(":", 1)[-1]
    assert outputs["TopicName"] == expected_name, (
        f"GetAtt Topic.TopicName was {outputs['TopicName']!r}, expected {expected_name!r} "
        f"(from the topic arn {topic_arn!r})"
    )

    # Independent read at the destination: SNS's own attributes must carry the
    # property the template declared.
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert attrs["DisplayName"] == display_name, (
        f"expected DisplayName {display_name!r}, got {attrs['DisplayName']!r}"
    )

    cfn.delete_stack(StackName=stack_id)
    deleted = _wait_stack(cfn, stack_id)
    assert deleted == "DELETE_COMPLETE", f"expected DELETE_COMPLETE, got {deleted!r}"

    code, message = _wait_gone(lambda: sns.get_topic_attributes(TopicArn=topic_arn))
    assert code == "NotFound", f"expected NotFound after stack delete, got {code!r}"
    assert message == "Topic does not exist", f"expected the standard NotFound message, got {message!r}"


def _wait_gone(call, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    """Poll ``call`` until it raises SNS's not-found error; the physical delete may
    lag DELETE_COMPLETE. Returns ``(code, message)``."""
    deadline = time.monotonic() + timeout_s
    last_code, last_message = None, None
    while time.monotonic() < deadline:
        try:
            call()
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            last_message = exc.response["Error"]["Message"]
            if last_code == "NotFound":
                return last_code, last_message
        else:
            last_code, last_message = None, None
        time.sleep(interval_s)
    raise AssertionError(
        f"topic still answering after {timeout_s}s of polling "
        f"(last_code={last_code!r}, last_message={last_message!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
