"""stack-and-system-tags-land-on-created-resources."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-and-system-tags-land-on-created-resources"
GROUP = "tags"
SERVICES = ["cloudformation", "sns", "sqs"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic"},
            "Queue": {"Type": "AWS::SQS::Queue"},
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:representation", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack-level Tag lands on both a created SNS topic and SQS queue, but the three
    CloudFormation system tags land on the topic only -- the queue carries the stack tag alone."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    stack = ctx.unique_name("sim2real-xsvc-tags-")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))

    cfn.create_stack(
        StackName=stack,
        TemplateBody=_template(),
        Tags=[{"Key": "sim2real-env", "Value": "fidelity-check"}],
    )
    status = _wait_terminal(cfn, stack)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended in {status!r}, expected CREATE_COMPLETE"

    stack_desc = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    stack_id = stack_desc["StackId"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack_desc.get("Outputs", [])}
    topic_arn = outputs["TopicArn"]
    queue_url = outputs["QueueUrl"]

    # --- the SNS topic: stack tag plus all three CloudFormation system tags -------------------
    topic_tags = {
        t["Key"]: t["Value"]
        for t in sns.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]
    }
    assert topic_tags.get("sim2real-env") == "fidelity-check", (
        f"the stack tag did not land on the SNS topic; got {topic_tags!r}"
    )
    assert topic_tags.get("aws:cloudformation:stack-name") == stack, (
        f"expected the topic's aws:cloudformation:stack-name system tag to read {stack!r}, "
        f"got {topic_tags.get('aws:cloudformation:stack-name')!r} (all tags: {topic_tags!r})"
    )
    assert topic_tags.get("aws:cloudformation:logical-id") == "Topic", (
        f"expected the topic's aws:cloudformation:logical-id system tag to read 'Topic', got "
        f"{topic_tags.get('aws:cloudformation:logical-id')!r} (all tags: {topic_tags!r})"
    )
    assert topic_tags.get("aws:cloudformation:stack-id") == stack_id, (
        f"expected the topic's aws:cloudformation:stack-id system tag to read {stack_id!r}, "
        f"got {topic_tags.get('aws:cloudformation:stack-id')!r} (all tags: {topic_tags!r})"
    )

    # --- the SQS queue: the SAME stack, the SAME Tags block, a DIFFERENT outcome ---------------
    # ListQueueTags never gains the three system tags, even after a 25s poll: this is not
    # propagation lag, CloudFormation does not emit them for this resource type.
    queue_tags = _poll_queue_tags(sqs, queue_url, timeout_s=25.0)
    assert queue_tags == {"sim2real-env": "fidelity-check"}, (
        f"expected the queue to carry ONLY the stack tag -- real AWS does not propagate the "
        f"aws:cloudformation:* system tags to AWS::SQS::Queue -- got {queue_tags!r}"
    )


def _wait_terminal(cfn, stack_name: str, *, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach a terminal status within {timeout_s}s (last={last!r})")


def _poll_queue_tags(sqs, queue_url: str, *, timeout_s: float, interval_s: float = 5.0) -> dict:
    """The queue's tags, re-read until the deadline so a late-arriving system tag is caught."""
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while True:
        last = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags") or {}
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


def _delete_stack_and_wait(cfn, stack_name: str, *, timeout_s: float = 300.0) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if status in ("DELETE_COMPLETE",):
            return
        if status == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_name} DELETE_FAILED")
        time.sleep(5.0)
    raise RuntimeError(f"stack {stack_name} still deleting after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
