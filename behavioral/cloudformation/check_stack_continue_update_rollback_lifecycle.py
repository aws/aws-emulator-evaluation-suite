"""stack-continue-update-rollback-lifecycle."""
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


CHECK = "stack-continue-update-rollback-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A stack in UPDATE_ROLLBACK_FAILED reaches UPDATE_ROLLBACK_COMPLETE via ContinueUpdateRollback,
    and ContinueUpdateRollback on the deleted stack fails ValidationError.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    # An SNS-backed Custom::Resource fanned out to SQS lets the check answer each handler request.
    queue_url, queue_arn = _create_queue(ctx, sqs)
    topic_arn = _create_topic(ctx, sns)
    _subscribe_queue_to_topic(ctx, sns, sqs, queue_url, queue_arn, topic_arn)

    stack_name = ctx.unique_name("sim2real-continueupdate-")
    physical_id = f"sim2real-probe-{stack_name[-12:]}"

    def _delete_cleanup() -> None:
        _safe(lambda: cfn.delete_stack(StackName=stack_name))
        # Drain and answer any Delete request so the stack doesn't get stuck.
        _drain_and_answer(ctx, sqs, queue_url, "SUCCESS", physical_id, timeout_s=45.0)

    ctx.on_cleanup(_delete_cleanup)

    template_v1 = _template(topic_arn, marker="v1")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template_v1),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    req = _next_request(sqs, queue_url, timeout_s=90.0)
    assert req["RequestType"] == "Create", f"expected Create, got {req['RequestType']!r}"
    _respond(ctx, req, "SUCCESS", physical_id)

    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"setup create failed: {status}"

    # Fail the v2 update, forcing UPDATE_FAILED.
    template_v2 = _template(topic_arn, marker="v2")
    cfn.update_stack(StackName=stack_name, TemplateBody=json.dumps(template_v2))
    req = _next_request(sqs, queue_url, timeout_s=90.0)
    assert req["RequestType"] == "Update", f"expected Update, got {req['RequestType']!r}"
    assert req["ResourceProperties"]["Marker"] == "v2", (
        f"expected Marker=v2, got {req['ResourceProperties'].get('Marker')!r}"
    )
    _respond(ctx, req, "FAILED", physical_id, reason="synthetic failure to force UPDATE_FAILED")

    # The automatic rollback sends an Update back to v1; failing it forces UPDATE_ROLLBACK_FAILED.
    req = _next_request(sqs, queue_url, timeout_s=90.0)
    assert req["RequestType"] == "Update", f"expected Update, got {req['RequestType']!r}"
    assert req["ResourceProperties"]["Marker"] == "v1", (
        f"expected rollback Marker=v1, got {req['ResourceProperties'].get('Marker')!r}"
    )
    _respond(ctx, req, "FAILED", physical_id, reason="synthetic failure to force UPDATE_ROLLBACK_FAILED")

    rollback_failed = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("UPDATE_ROLLBACK_FAILED", "UPDATE_ROLLBACK_COMPLETE"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert rollback_failed == "UPDATE_ROLLBACK_FAILED", (
        f"expected UPDATE_ROLLBACK_FAILED, got {rollback_failed}"
    )

    # ContinueUpdateRollback retries the revert-to-v1 update; this time it succeeds.
    cfn.continue_update_rollback(StackName=stack_name)
    req = _next_request(sqs, queue_url, timeout_s=90.0)
    assert req["RequestType"] == "Update", f"expected Update, got {req['RequestType']!r}"
    _respond(ctx, req, "SUCCESS", physical_id)

    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final_status == "UPDATE_ROLLBACK_COMPLETE", (
        f"ContinueUpdateRollback ended in {final_status}, expected UPDATE_ROLLBACK_COMPLETE"
    )

    cfn.delete_stack(StackName=stack_name)
    req = _next_request(sqs, queue_url, timeout_s=90.0)
    assert req["RequestType"] == "Delete", f"expected Delete, got {req['RequestType']!r}"
    _respond(ctx, req, "SUCCESS", physical_id)

    _wait_deleted(cfn, stack_name, timeout_s=120.0)

    dead_code, dead_msg = _client_error(lambda: cfn.continue_update_rollback(StackName=stack_name))
    assert dead_code == "ValidationError", (
        f"expected ValidationError from ContinueUpdateRollback on a deleted stack, got {dead_code!r}"
    )
    assert dead_msg == f"Stack: {stack_name} does not exist", dead_msg




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
        QueueName=ctx.unique_name("sim2real-cfn-cr-q-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _safe(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx, sns) -> str:
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cfn-cr-topic-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sns.delete_topic(TopicArn=arn)))
    return arn


def _wait_deleted(cfn, stack_name: str, timeout_s: float = 120.0) -> None:
    """Wait until the stack reaches DELETE_COMPLETE or vanishes from DescribeStacks."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
            if last == "DELETE_COMPLETE":
                return
            if last == "DELETE_FAILED":
                raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ValidationError":
                return
            raise
        time.sleep(3.0)
    raise AssertionError(f"stack {stack_name} not deleted within {timeout_s}s (last={last!r})")


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, else raise."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


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
