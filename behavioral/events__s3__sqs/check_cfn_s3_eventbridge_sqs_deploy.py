"""cfn-s3-eventbridge-sqs-deploy."""

from __future__ import annotations

import json
import pathlib
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3-eventbridge-sqs-deploy"

GROUP = "deployment-order"

SERVICES = ["events", "s3", "sqs"]

DEPLOYMENTS = pathlib.Path(__file__).parent / "deployments"


def _is_s3_test_event(body: object) -> bool:
    """True for S3's one-off destination-validation handshake message.

    When a queue is first attached as an S3 notification destination, S3 posts
    {"Service":"Amazon S3","Event":"s3:TestEvent", ...} to prove it can write to
    the queue. It carries no "Records" and is NOT an object event, so it must
    never be mistaken for one (nor counted as an over-delivery).
    """
    return isinstance(body, dict) and body.get("Event") == "s3:TestEvent"


def _wait_for_s3_records(
    ctx,
    queue_url: str,
    expected_count: int = 1,
    timeout_s: float = 90,
) -> list[dict]:
    """Poll SQS for real S3 object-event notifications, discarding s3:TestEvent."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    out: list[dict] = []
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if _is_s3_test_event(body):
                continue
            out.append({"body": body, "attributes": m.get("MessageAttributes", {})})
    if len(out) < expected_count:
        raise AssertionError(
            f"expected {expected_count} S3 notification(s), got {len(out)} within {timeout_s}s"
        )
    return out


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CloudFormation-deployed S3 bucket + queue policy delivers ObjectCreated events to SQS."""
    template = (DEPLOYMENTS / "s3-sqs-notification.yaml").read_text()
    # Bucket is explicitly named to break the bucket <-> queue-policy dependency
    # cycle; the name must be globally unique and DNS-compatible (lowercase).
    bucket_name = ctx.unique_name("cfn-s3sqs-").lower()
    result = _deploy_cfn(ctx, template, parameters={"BucketName": bucket_name})

    outputs = result.get("outputs", result)
    bucket_name = outputs["BucketName"]
    queue_url = outputs["QueueUrl"]

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket_name, Key="cfn-trigger.txt", Body=b"cfn-data")

    try:
        messages = _wait_for_s3_records(ctx, queue_url, expected_count=1, timeout_s=120)
        assert messages, (
            "expected CFN-deployed S3->SQS notification pipeline to deliver a message"
        )
        record = messages[0]["body"]["Records"][0]
        assert record["s3"]["bucket"]["name"] == bucket_name, (
            f"expected notification for bucket {bucket_name!r}, "
            f"got {record['s3']['bucket']['name']!r}"
        )
        assert record["s3"]["object"]["key"] == "cfn-trigger.txt", (
            f"expected notification for key 'cfn-trigger.txt', "
            f"got {record['s3']['object']['key']!r}"
        )
    finally:
        # CFN cannot delete a non-empty bucket, so drain it or stack teardown
        # (and therefore account cleanup) fails.
        try:
            s3.delete_object(Bucket=bucket_name, Key="cfn-trigger.txt")
        except Exception:
            pass


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


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

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
