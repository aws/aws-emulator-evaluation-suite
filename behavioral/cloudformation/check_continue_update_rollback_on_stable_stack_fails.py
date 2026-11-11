"""continue-update-rollback-on-stable-stack-fails."""
from __future__ import annotations

import json
import time
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "continue-update-rollback-on-stable-stack-fails"
GROUP = 'rollback'
SERVICES = ['cloudformation']


def _error(fn):
    """Call fn(); return (code, message) of the ClientError raised. A call that
    succeeds raises AssertionError: the target accepted what AWS refuses."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")

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

def _template(topic_arn: str, marker: str) -> dict[str, Any]:
    return {
        "Resources": {
            "Probe": {
                "Type": "Custom::Sim2RealProbe",
                "Properties": {"ServiceToken": topic_arn, "Marker": marker},
            }
        }
    }

def _next_request(sqs, queue_url: str, timeout_s: float = 90.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=15)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            envelope = json.loads(msg["Body"])
            return json.loads(envelope["Message"])
    raise AssertionError(f"no custom-resource request arrived within {timeout_s}s")

def _drain_and_answer(ctx, sqs, queue_url: str, status: str, physical_id: str, timeout_s: float = 45.0) -> None:
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

def _respond(ctx, request: dict[str, Any], status: str, physical_resource_id: str, reason: str | None = None) -> None:
    body = json.dumps({
        "Status": status,
        "Reason": reason or "sim2real synthetic custom resource response",
        "PhysicalResourceId": physical_resource_id,
        "StackId": request["StackId"],
        "RequestId": request["RequestId"],
        "LogicalResourceId": request["LogicalResourceId"],
        "NoEcho": False,
        "Data": {},
    }).encode("utf-8")
    http_req = _routed_request(ctx, request["ResponseURL"], data=body, method="PUT", headers={"content-type": ""})
    urllib.request.urlopen(http_req, timeout=30)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """ContinueUpdateRollback on a CREATE_COMPLETE stack is a ValidationError that leaves it unchanged;
    once the same stack is UPDATE_ROLLBACK_FAILED, the call succeeds and recovers it to
    UPDATE_ROLLBACK_COMPLETE."""
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cur-q-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _safe(lambda: sqs.delete_queue(QueueUrl=queue_url)))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cur-topic-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sns.delete_topic(TopicArn=topic_arn)))

    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    })})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sns.unsubscribe(SubscriptionArn=sub_arn)))

    name = ctx.unique_name("sim2real-behav-continue-")
    physical_id = f"sim2real-probe-{name[-12:]}"

    def _delete_cleanup() -> None:
        _safe(lambda: cf.delete_stack(StackName=name))
        _drain_and_answer(ctx, sqs, queue_url, "SUCCESS", physical_id, timeout_s=45.0)

    ctx.on_cleanup(_delete_cleanup)

    cf.create_stack(
        StackName=name,
        TemplateBody=json.dumps(_template(topic_arn, "v1")),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    req = _next_request(sqs, queue_url)
    assert req["RequestType"] == "Create"
    _respond(ctx, req, "SUCCESS", physical_id)
    status = _poll_until(
        lambda: cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED"),
    )
    assert status == "CREATE_COMPLETE", f"setup create failed: {status}"

    code, message = _error(lambda: cf.continue_update_rollback(StackName=name))
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected = "RollbackUpdatedStack cannot be called from current stack status"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    unaffected = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    assert unaffected == "CREATE_COMPLETE", f"rejected call must not perturb status, got {unaffected!r}"

    # Reach UPDATE_ROLLBACK_FAILED: fail the update, then fail the automatic rollback update.
    cf.update_stack(StackName=name, TemplateBody=json.dumps(_template(topic_arn, "v2")))
    req = _next_request(sqs, queue_url)
    assert req["RequestType"] == "Update" and req["ResourceProperties"]["Marker"] == "v2"
    _respond(ctx, req, "FAILED", physical_id, reason="sim2real forcing UPDATE_FAILED")

    req = _next_request(sqs, queue_url)
    assert req["RequestType"] == "Update" and req["ResourceProperties"]["Marker"] == "v1"
    _respond(ctx, req, "FAILED", physical_id, reason="sim2real forcing UPDATE_ROLLBACK_FAILED")

    stuck = _poll_until(
        lambda: cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("UPDATE_ROLLBACK_FAILED", "UPDATE_ROLLBACK_COMPLETE"),
    )
    assert stuck == "UPDATE_ROLLBACK_FAILED", f"expected UPDATE_ROLLBACK_FAILED, got {stuck!r}"

    cf.continue_update_rollback(StackName=name)
    req = _next_request(sqs, queue_url)
    assert req["RequestType"] == "Update"
    _respond(ctx, req, "SUCCESS", physical_id)
    recovered = _poll_until(
        lambda: cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"),
    )
    assert recovered == "UPDATE_ROLLBACK_COMPLETE", f"ContinueUpdateRollback did not recover: {recovered!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
