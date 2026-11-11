"""stack-update-cancel-then-continue-rollback."""
from __future__ import annotations

import json
import time
import urllib.request
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "stack-update-cancel-then-continue-rollback"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """CancelUpdateStack on an in-flight update rolls it back; a failed revert lands in
    UPDATE_ROLLBACK_FAILED and ContinueUpdateRollback retries it to UPDATE_ROLLBACK_COMPLETE.
    A Custom::Resource over SNS/SQS controls the forward and revert responses deterministically."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    queue_url, queue_arn = _create_queue(ctx, sqs)
    topic_arn = _create_topic(ctx, sns)
    _subscribe_queue_to_topic(ctx, sns, sqs, queue_url, queue_arn, topic_arn)

    stack_name = ctx.unique_name("sim2real-cancelcontinue-")
    physical_id = f"sim2real-probe-{stack_name[-12:]}"

    def _delete_cleanup() -> None:
        _safe(lambda: cfn.delete_stack(StackName=stack_name))
        # Drain and answer any Delete request so the stack doesn't get stuck.
        _drain_and_answer(ctx, sqs, queue_url, "SUCCESS", physical_id, timeout_s=60.0)

    ctx.on_cleanup(_delete_cleanup)

    # Positive control: v1 creates cleanly, proving the custom-resource wiring works.
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(topic_arn, "v1")),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    req = _next_request(sqs, queue_url, timeout_s=90.0)
    assert req["RequestType"] == "Create", req["RequestType"]
    _respond(ctx, req, "SUCCESS", physical_id)
    created = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert created == "CREATE_COMPLETE", f"setup create failed: {created}"

    # Leave the forward request unanswered so the update is still in flight when cancelled.
    cfn.update_stack(StackName=stack_name, TemplateBody=json.dumps(_template(topic_arn, "v2")))
    forward = _next_request(sqs, queue_url, timeout_s=90.0)
    assert forward["RequestType"] == "Update" and forward["ResourceProperties"]["Marker"] == "v2", forward
    in_progress = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert in_progress == "UPDATE_IN_PROGRESS", f"expected the forward update to still be pending, got {in_progress}"

    # CloudFormation abandons the pending forward request and asks for a revert to v1;
    # answering the stale forward request is harmless.
    cfn.cancel_update_stack(StackName=stack_name)
    _respond(ctx, forward, "SUCCESS", physical_id)

    revert = _next_request(sqs, queue_url, timeout_s=90.0)
    assert revert["RequestType"] == "Update" and revert["ResourceProperties"]["Marker"] == "v1", revert
    _respond(ctx, revert, "FAILED", physical_id, reason="synthetic failure to force UPDATE_ROLLBACK_FAILED")

    rollback_failed = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("UPDATE_ROLLBACK_FAILED", "UPDATE_ROLLBACK_COMPLETE"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert rollback_failed == "UPDATE_ROLLBACK_FAILED", (
        f"a revert that fails should stick the stack in UPDATE_ROLLBACK_FAILED, got {rollback_failed}"
    )

    # ContinueUpdateRollback retries the same revert; this time it succeeds.
    cfn.continue_update_rollback(StackName=stack_name)
    retry = _next_request(sqs, queue_url, timeout_s=90.0)
    assert retry["RequestType"] == "Update" and retry["ResourceProperties"]["Marker"] == "v1", retry
    _respond(ctx, retry, "SUCCESS", physical_id)

    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final_status == "UPDATE_ROLLBACK_COMPLETE", (
        f"ContinueUpdateRollback did not stabilize the stack: {final_status}"
    )

    # ContinueUpdateRollback is rejected once the stack is stable.
    code, message = _error_code(lambda: cfn.continue_update_rollback(StackName=stack_name))
    assert code == "ValidationError", f"expected ValidationError on a stable stack, got {code}"
    assert message == "RollbackUpdatedStack cannot be called from current stack status", message


def _template(topic_arn: str, marker: str) -> dict[str, Any]:
    return {
        "Resources": {
            "Probe": {
                "Type": "Custom::Sim2RealProbe",
                "Properties": {"ServiceToken": topic_arn, "Marker": marker},
            }
        }
    }


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("AWS.SimpleQueueService.NonExistentQueue", "NotFound", "QueueDoesNotExist",) or
            (exc.response["Error"]["Code"] == "ValidationError"
             and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _error_code(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_queue(ctx, sqs) -> tuple[str, str]:
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cfn-cc-q-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _safe(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx, sns) -> str:
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cfn-cc-topic-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sns.delete_topic(TopicArn=arn)))
    return arn


def _subscribe_queue_to_topic(ctx, sns, sqs, queue_url: str, queue_arn: str, topic_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
    sub_arn = sub["SubscriptionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sns.unsubscribe(SubscriptionArn=sub_arn)))


def _next_request(sqs, queue_url: str, timeout_s: float = 90.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=15)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            envelope = json.loads(msg["Body"])
            return json.loads(envelope["Message"])
    raise AssertionError(f"no custom-resource request arrived within {timeout_s}s")


def _drain_and_answer(ctx, sqs, queue_url: str, status: str, physical_id: str, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                envelope = json.loads(msg["Body"])
                request = json.loads(envelope["Message"])
                _respond(ctx, request, status, physical_id)
            except Exception:
                pass


def _respond(ctx, request: dict[str, Any], status: str, physical_resource_id: str, reason: str | None = None, data: dict[str, Any] | None = None) -> None:
    body = json.dumps(
        {
            "Status": status,
            "Reason": reason or "sim2real synthetic custom resource response",
            "PhysicalResourceId": physical_resource_id,
            "StackId": request["StackId"],
            "RequestId": request["RequestId"],
            "LogicalResourceId": request["LogicalResourceId"],
            "NoEcho": False,
            "Data": data or {},
        }
    ).encode("utf-8")
    http_req = _routed_request(ctx, request["ResponseURL"], data=body, method="PUT", headers={"content-type": ""})
    urllib.request.urlopen(http_req, timeout=30)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
