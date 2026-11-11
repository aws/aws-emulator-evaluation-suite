"""cfn-deploy-s3-notification-sqs-stack-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-s3-notification-sqs-stack-positive"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


def _msg_body_json(msg: dict) -> dict:
    """Return message body as a parsed dict, whether harness returns str or dict."""
    raw = msg.get("Body") or msg.get("body", "{}")
    if isinstance(raw, dict):
        return raw
    return json.loads(raw)


def _drain_s3_test_events(sqs_client, queue_url: str, timeout_s: int = 15) -> None:
    """Drain S3 TestEvent messages that AWS sends when configuring bucket notifications.

    When a bucket notification is configured, S3 sends a 's3:TestEvent' to each destination.
    This helper drains those probe messages so checks only see real object events.
    """

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs_client.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            break
        for msg in msgs:
            raw = _msg_body_json(msg)
            # If it is a test event, delete it; otherwise leave it (shouldn't happen pre-PutObject)
            if raw.get("Event") == "s3:TestEvent" or raw.get("Service") == "Amazon S3":
                sqs_client.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=msg["ReceiptHandle"],
                )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Deploy S3+SQS+notification via CFN; PutObject triggers queue message."""
    template = (DEPLOYMENTS / "s3-sqs-notification.yaml").read_text()
    result = _deploy_cfn(ctx, template)
    bucket_name = result["outputs"]["BucketName"]
    queue_url = result["outputs"]["QueueUrl"]

    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    _drain_s3_test_events(sqs, queue_url)
    s3.put_object(Bucket=bucket_name, Key="deploy-test/item.txt", Body=b"hello")

    messages = _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=30)
    assert messages, "No notification message received in SQS queue"

    # CloudFormation cannot delete a non-empty bucket, so empty it before the stack delete.
    for obj in s3.list_objects_v2(Bucket=bucket_name).get("Contents", []):
        s3.delete_object(Bucket=bucket_name, Key=obj["Key"])

    body = _msg_body_json(messages[0])
    records = body.get("Records", [])
    assert records, f"No Records in notification body: {body}"
    key = records[0]["s3"]["object"]["key"]
    assert key == "deploy-test/item.txt", f"Unexpected object key: {key}"


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


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
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
