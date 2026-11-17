"""generated-resource-names-resolve-at-owning-service-and-release-on-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generated-resource-names-resolve-at-owning-service-and-release-on-delete"
GROUP = "naming"
SERVICES = ["cloudformation", "sns", "sqs", "ssm"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
})
_SUFFIX = re.compile(r"^[A-Za-z0-9]{12}$")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _wait_terminal(cf, stack_name, timeout_s=300.0):
    """Poll DescribeStacks until a terminal StackStatus; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_name} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _delete_stack(cf, stack_name):
    """Delete the stack and wait for DELETE_COMPLETE; a failed delete raises.

    DescribeStacks may itself start refusing the name once the delete finishes, exactly as
    CloudFormation's own stack_delete_complete waiter treats that refusal as done.
    """
    cf.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 300.0
    while True:
        try:
            status = cf.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {stack_name} does not exist"):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_name} delete ended {status!r}")
        time.sleep(2)


def _physical_id(resources, logical_id):
    for r in resources:
        if r.get("LogicalResourceId") == logical_id:
            return r.get("PhysicalResourceId")
    raise AssertionError(f"no resource named {logical_id!r} in {resources!r}")


def _expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly the (code, message) pair."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(explicit_topic_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AutoTopic": {"Type": "AWS::SNS::Topic"},
            "AutoQueue": {"Type": "AWS::SQS::Queue"},
            "AutoParameter": {"Type": "AWS::SSM::Parameter",
                               "Properties": {"Type": "String", "Value": "v1"}},
            "ExplicitTopic": {"Type": "AWS::SNS::Topic",
                               "Properties": {"TopicName": explicit_topic_name}},
            "SubQueue": {"Type": "AWS::SQS::Queue",
                         "Properties": {
                             "QueueName": {"Fn::Sub": "${ExplicitTopic.TopicName}-x"}}},
        },
    })


_TOPIC_GONE = ("NotFound", "Topic does not exist")
_QUEUE_GONE = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")
_PARAM_GONE = ("ParameterNotFound", "")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack's unnamed SNS topic, SQS queue and SSM parameter get generated physical names
    that resolve at their owning service, an explicit TopicName yields exactly that ARN, and
    every name is refused by its service once the stack is deleted."""
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")

    stack_name = ctx.unique_name("sim2real-behav-stk-")
    explicit_topic_name = ctx.unique_name("sim2real-behav-t-")

    cf.create_stack(StackName=stack_name, TemplateBody=_template(explicit_topic_name))
    ctx.on_cleanup(_teardown(lambda: _delete_stack(cf, stack_name), "ValidationError"))
    status = _wait_terminal(cf, stack_name)
    assert status == "CREATE_COMPLETE", f"stack {stack_name} ended {status!r}"

    resources = cf.describe_stack_resources(StackName=stack_name)["StackResources"]
    auto_topic_arn = _physical_id(resources, "AutoTopic")
    auto_queue_url = _physical_id(resources, "AutoQueue")
    auto_param_name = _physical_id(resources, "AutoParameter")
    explicit_topic_arn = _physical_id(resources, "ExplicitTopic")
    subqueue_url = _physical_id(resources, "SubQueue")

    # Generated names follow "<StackName>-<LogicalId>-<suffix>" (SSM: "CFN-<LogicalId>-<suffix>")
    # with a 12-character mixed-case alphanumeric suffix.
    auto_topic_name = auto_topic_arn.rsplit(":", 1)[-1]
    m = re.match(rf"^{re.escape(stack_name)}-AutoTopic-([A-Za-z0-9]+)$", auto_topic_name)
    assert m and _SUFFIX.match(m.group(1)), (
        f"AutoTopic name {auto_topic_name!r} does not match "
        f"'{stack_name}-AutoTopic-<12 char mixed-case alnum suffix>'"
    )
    assert len(auto_topic_name) <= 256, f"topic name {len(auto_topic_name)} chars > 256"

    auto_queue_name = auto_queue_url.rsplit("/", 1)[-1]
    m = re.match(rf"^{re.escape(stack_name)}-AutoQueue-([A-Za-z0-9]+)$", auto_queue_name)
    assert m and _SUFFIX.match(m.group(1)), (
        f"AutoQueue name {auto_queue_name!r} does not match "
        f"'{stack_name}-AutoQueue-<12 char mixed-case alnum suffix>'"
    )
    assert len(auto_queue_name) <= 80, f"queue name {len(auto_queue_name)} chars > 80"

    m = re.match(r"^CFN-AutoParameter-([A-Za-z0-9]+)$", auto_param_name)
    assert m and _SUFFIX.match(m.group(1)), (
        f"AutoParameter name {auto_param_name!r} does not match "
        f"'CFN-AutoParameter-<12 char mixed-case alnum suffix>'"
    )
    assert len(auto_param_name) <= 2048, f"parameter name {len(auto_param_name)} chars > 2048"

    # Each generated name resolves at its owning service.
    attrs = sns.get_topic_attributes(TopicArn=auto_topic_arn)["Attributes"]
    assert attrs["TopicArn"] == auto_topic_arn, (
        f"GetTopicAttributes TopicArn {attrs['TopicArn']!r} != CFN physical id {auto_topic_arn!r}"
    )
    got_url = sqs.get_queue_url(QueueName=auto_queue_name)["QueueUrl"]
    assert got_url == auto_queue_url, (
        f"GetQueueUrl {got_url!r} != CFN physical id {auto_queue_url!r}"
    )
    value = ssm.get_parameter(Name=auto_param_name)["Parameter"]["Value"]
    assert value == "v1", f"GetParameter value {value!r} != declared Value 'v1'"

    # An explicit TopicName yields exactly that ARN.
    expected_explicit_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{explicit_topic_name}"
    assert explicit_topic_arn == expected_explicit_arn, (
        f"ExplicitTopic ARN {explicit_topic_arn!r} != expected {expected_explicit_arn!r}"
    )

    # A sibling queue whose QueueName is Fn::Sub '${Topic.TopicName}-x' is created under
    # exactly that string.
    subqueue_name = subqueue_url.rsplit("/", 1)[-1]
    expected_subqueue_name = f"{explicit_topic_name}-x"
    assert subqueue_name == expected_subqueue_name, (
        f"SubQueue name {subqueue_name!r} != expected {expected_subqueue_name!r}"
    )
    got_sub_url = sqs.get_queue_url(QueueName=subqueue_name)["QueueUrl"]
    assert got_sub_url == subqueue_url, (
        f"GetQueueUrl {got_sub_url!r} != CFN physical id {subqueue_url!r}"
    )

    _delete_stack(cf, stack_name)

    # Every name is refused by its owning service once the stack is deleted.
    _expect_error(lambda: sns.get_topic_attributes(TopicArn=auto_topic_arn), *_TOPIC_GONE)
    _expect_error(lambda: sns.get_topic_attributes(TopicArn=explicit_topic_arn), *_TOPIC_GONE)
    _expect_error(lambda: sqs.get_queue_url(QueueName=auto_queue_name), *_QUEUE_GONE)
    _expect_error(lambda: sqs.get_queue_url(QueueName=subqueue_name), *_QUEUE_GONE)
    _expect_error(lambda: ssm.get_parameter(Name=auto_param_name), *_PARAM_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
