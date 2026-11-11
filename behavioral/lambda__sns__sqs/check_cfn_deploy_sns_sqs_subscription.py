"""cfn-deploy-sns-sqs-subscription."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sns-sqs-subscription"

GROUP = "deployment-order"

SERVICES = ["lambda", "sns", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed SNS topic + SQS subscription with a FilterPolicy delivers the
    matching message, withholds the non-matching one, and the drained queue polls to 0 visible."""
    template = (DEPLOYMENTS / "cfn-sns-sqs-subscription.yaml").read_text()
    result = _deploy_cfn(ctx, template)
    topic_arn = result["outputs"]["TopicArn"]
    queue_url = result["outputs"]["QueueUrl"]
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    sns.publish(
        TopicArn=topic_arn,
        Message="cfn-shipping-event",
        MessageAttributes={"category": {"DataType": "String", "StringValue": "shipping"}},
    )
    start = time.monotonic()
    sns.publish(
        TopicArn=topic_arn,
        Message="cfn-order-event",
        MessageAttributes={"category": {"DataType": "String", "StringValue": "orders"}},
    )
    messages = _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60)
    matching_latency_s = time.monotonic() - start
    assert (
        len(messages) == 1 and messages[0]["body"].get("Message") == "cfn-order-event"
    ), (
        f"CFN-deployed SNS->SQS subscription did not deliver the filtered message: {[m['body'] for m in messages]}"
    )

    hold_s = max(3.0 * matching_latency_s, 15.0)
    leaked = _drain_for(ctx, queue_url, hold_s)
    assert not leaked, (
        f"FilterPolicy category=orders let a non-matching message through within {hold_s:.1f}s "
        f"of the matching delivery (which took {matching_latency_s:.1f}s): {[m['body'] for m in leaked]}"
    )
    _poll_queue_counters(ctx, sqs, queue_url, {"ApproximateNumberOfMessages": "0"})


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_queue_counters(ctx, sqs, queue_url, expected, cap_s=90.0):
    """Poll GetQueueAttributes until every named counter equals its expected string value.

    The ApproximateNumberOf* counters may lag up to a minute after producers stop
    (SQS GetQueueAttributes docs), so a single read is not a verdict."""
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=list(expected))["Attributes"]
        observed = {name: attrs.get(name) for name in expected}
        if observed == expected:
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s counter wait ended (last observed {observed}); not graded"
                )
            raise AssertionError(f"queue counters never reached {expected} within {cap_s}s; last observed {observed}")
        time.sleep(3)


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


def _drain_for(ctx, queue_url, duration_s, delete=True):
    """Receive from the queue for duration_s (never raises); return whatever arrived."""
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            collected.append({"body": body, "message_id": msg["MessageId"]})
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    return collected


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
