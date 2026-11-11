"""deploy-sns-topic-maximum-message-size-boundary-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sns-topic-maximum-message-size-boundary-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns"]

_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _template(topic_name: str, max_message_size: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": topic_name,
                    "MaximumMessageSize": max_message_size,
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


def _assert_rejected(ctx, cfn, sns, *, topic_name: str, size: int, reason: str) -> None:
    stack_name = ctx.unique_name("sim2real-cfn-snsval-bad-")
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(topic_name, size),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    status = _wait_terminal(cfn, stack_name)
    assert status == "ROLLBACK_COMPLETE", (
        f"expected MaximumMessageSize={size} to roll back, ended in {status!r}"
    )
    events = [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name)
              for e in page["StackEvents"]]
    stack_failed = [e.get("ResourceStatusReason") for e in events
                    if e["LogicalResourceId"] == stack_name and e["ResourceStatus"] == "CREATE_FAILED"]
    assert stack_failed == [_STACK_REASON], (
        f"the stack's CREATE_FAILED reasons were {stack_failed!r}, expected [{_STACK_REASON!r}]"
    )
    found = _validation_errors(cfn, stack_name)
    want = [(
        "Topic", "AWS::SNS::Topic", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        reason, "/Resources/Topic/Properties/MaximumMessageSize",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    assert resources == [], f"a stack rejected before provisioning reports resources {resources!r}"
    partition = stack_id.split(":")[1]
    topic_arn = f"arn:{partition}:sns:{ctx.region}:{ctx.account}:{topic_name}"
    got = _error(lambda: sns.get_topic_attributes(TopicArn=topic_arn))
    assert got == ("NotFound", "Topic does not exist"), (
        f"GetTopicAttributes on the refused topic {topic_name!r} answered {got!r}, "
        f"expected ('NotFound', 'Topic does not exist')"
    )

    _delete_stack(cfn, stack_name)
    code, message = _error(lambda: cfn.describe_stacks(StackName=stack_name))
    assert (code, message) == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
        f"DescribeStacks of the deleted rolled-back stack answered {(code, message)!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """An SNS topic's MaximumMessageSize fails CFN's property-value validation both below its
    minimum and above its maximum, before provisioning; the minimum and the maximum themselves
    deploy and SNS reads back each boundary."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")

    _assert_rejected(
        ctx, cfn, sns, topic_name=ctx.unique_name("sim2real-snsval-badmin-"), size=100,
        reason="#/MaximumMessageSize: 100 is not greater or equal to 1024",
    )
    _assert_rejected(
        ctx, cfn, sns, topic_name=ctx.unique_name("sim2real-snsval-badmax-"), size=2_000_000,
        reason="#/MaximumMessageSize: 2000000 is not less or equal to 1048576",
    )

    # Positive control: the minimum boundary deploys, then an in-place update to the maximum
    # boundary succeeds on the SAME topic, and SNS reads back each value through its own API.
    good_stack = ctx.unique_name("sim2real-cfn-snsval-good-")
    good_topic = ctx.unique_name("sim2real-snsval-good-")
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_topic, 1024),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"the control stack settled at {status!r}, expected CREATE_COMPLETE"

    topic_arn = cfn.describe_stack_resource(
        StackName=good_stack, LogicalResourceId="Topic"
    )["StackResourceDetail"]["PhysicalResourceId"]
    size = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["MaximumMessageSize"]
    assert size == "1024", f"expected MaximumMessageSize at its minimum of 1024, got {size!r}"

    cfn.update_stack(
        StackName=good_stack,
        TemplateBody=_template(good_topic, 1_048_576),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    status = _wait_terminal(cfn, good_stack)
    assert status == "UPDATE_COMPLETE", f"the update settled at {status!r}, expected UPDATE_COMPLETE"
    updated_arn = cfn.describe_stack_resource(
        StackName=good_stack, LogicalResourceId="Topic"
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert updated_arn == topic_arn, (
        f"a MaximumMessageSize update must mutate the SAME topic, but the ARN changed "
        f"from {topic_arn!r} to {updated_arn!r}"
    )
    size = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["MaximumMessageSize"]
    assert size == "1048576", f"expected MaximumMessageSize at its maximum of 1048576, got {size!r}"

    _delete_stack(cfn, good_stack)
    code, message = _error(lambda: sns.get_topic_attributes(TopicArn=topic_arn))
    assert (code, message) == ("NotFound", "Topic does not exist"), (
        f"the deleted control topic's GetTopicAttributes answered {(code, message)!r}"
    )


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
