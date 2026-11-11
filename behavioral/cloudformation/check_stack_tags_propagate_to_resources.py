"""stack-tags-propagate-to-resources."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-tags-propagate-to-resources"
GROUP = 'tags'
SERVICES = ['cloudformation']


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=180):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _client_error(fn, what):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; raise if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")

def _create_and_wait(ctx, cf, template, *, parameters=None, tags=None, capabilities=None):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return (name, stack_id)."""
    name = ctx.unique_name("sim2real-behav-stk-")
    kwargs = {"StackName": name, "TemplateBody": template}
    if parameters:
        kwargs["Parameters"] = parameters
    if tags:
        kwargs["Tags"] = tags
    if capabilities:
        kwargs["Capabilities"] = capabilities
    stack_id = cf.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name, stack_id


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Stack-level tags propagate to resources that support tagging (SNS topic)."""
    cf = ctx.client("cloudformation")
    tags = [{"Key": "sim2real-propagate", "Value": "yes"}]
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Topic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": ctx.unique_name("sim2real-behav-topic-"),
                    },
                }
            },
        }
    )
    name, stack_id = _create_and_wait(ctx, cf, template, tags=tags)
    resp = cf.list_stack_resources(StackName=name)
    topic_arn = None
    for r in resp["StackResourceSummaries"]:
        if r["ResourceType"] == "AWS::SNS::Topic":
            topic_arn = r["PhysicalResourceId"]
            break
    if not topic_arn:
        raise AssertionError("SNS Topic not found in stack resources")
    sns = ctx.client("sns")
    tag_resp = sns.list_tags_for_resource(ResourceArn=topic_arn)
    tag_map = {t["Key"]: t["Value"] for t in tag_resp.get("Tags", [])}
    assert tag_map.get("sim2real-propagate") == "yes", (
        f"Tag not propagated to SNS topic. Tags: {tag_map}"
    )

    # The stack owns the topic it created, so deleting the stack must cascade: the
    # topic becomes both unreadable and unmutatable, not merely absent from a list.
    # Poll by StackId, not name: a deleted stack drops
    # out of name-based DescribeStacks (ValidationError) around the same time it
    # reaches DELETE_COMPLETE, so a name-based poll can never observe the terminal
    # status -- it stays addressable by StackId, exactly as the initial CREATE poll
    # was by name.
    cf.delete_stack(StackName=name)
    del_status = _wait_terminal(cf, stack_id)
    assert del_status == "DELETE_COMPLETE", (
        f"Stack {name} delete ended in {del_status}, expected DELETE_COMPLETE"
    )

    read_code, read_msg = _client_error(
        lambda: sns.get_topic_attributes(TopicArn=topic_arn), "GetTopicAttributes on the deleted topic"
    )
    assert read_code == "NotFound", (
        f"GetTopicAttributes on the cascade-deleted topic: expected NotFound, got {read_code!r}"
    )
    assert read_msg == "Topic does not exist", read_msg
    mutate_code, mutate_msg = _client_error(
        lambda: sns.set_topic_attributes(
            TopicArn=topic_arn, AttributeName="DisplayName", AttributeValue="x"
        ),
        "SetTopicAttributes on the deleted topic",
    )
    assert mutate_code == "NotFound", (
        f"SetTopicAttributes on the cascade-deleted topic: expected NotFound, got {mutate_code!r}"
    )
    assert mutate_msg == "Topic does not exist", mutate_msg

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
