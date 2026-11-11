"""e2e-create-use-observe-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-create-use-observe-delete"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Cloud Control-created SQS queue reaches SUCCESS, delivers a message and echoes its config
    via GetResource; after DeleteResource both the Cloud Control view and the queue itself are gone
    (SQS reports NonExistentQueue within its documented 60 s deletion window)."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    queue_name = ctx.unique_name("sim2real-cc-e2e-")
    desired_state = json.dumps(
        {
            "QueueName": queue_name,
            "VisibilityTimeout": 30,
            "Tags": [{"Key": "sim2real:check", "Value": CHECK}],
        }
    )

    create_resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)
    create_event = _wait_for_progress(cc, create_resp["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", create_event
    queue_url = create_event["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(cc, queue_url))

    # Exercise the real data plane.
    sqs.send_message(QueueUrl=queue_url, MessageBody="e2e-consequence")
    deadline = time.monotonic() + 20
    delivered = None
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            delivered = msgs[0]["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            break
    assert delivered == "e2e-consequence", (
        f"expected to receive the message body 'e2e-consequence' from the cloudcontrol-created "
        f"queue, got {delivered!r}"
    )

    # Observe the consequence/config via GetResource.
    props = _get_properties(cc, "AWS::SQS::Queue", queue_url)
    assert props["VisibilityTimeout"] == 30, (
        f"cloudcontrol get_resource reports VisibilityTimeout {props['VisibilityTimeout']!r}, "
        "desired state asked for 30"
    )
    assert props["QueueName"] == queue_name, (
        f"cloudcontrol get_resource reports QueueName {props['QueueName']!r}, expected "
        f"{queue_name!r}"
    )

    # Delete through Cloud Control.
    delete_resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
    delete_event = _wait_for_progress(cc, delete_resp["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", delete_event

    # Confirm the consequence is gone: Cloud Control view is gone...
    code, status, message = _error(
        lambda: cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url),
        "cloudcontrol get_resource after delete_resource",
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from cloudcontrol get_resource after delete, "
        f"got {code!r}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx from get_resource after delete, got {status!r}"
    message_head, _, request_id = message.partition(", RequestToken: ")
    expected_message = f"{create_event['TypeName']} Handler returned status FAILED: Resource of type '{create_event['TypeName']}' with identifier '{queue_url}' was not found. (HandlerErrorCode: NotFound"
    assert message_head == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)", request_id), f"unexpected request id in {message!r}"
    # ListResources converges after a delete, so absence is a bounded poll.
    deadline = time.monotonic() + 60.0
    while True:
        listed = [
            d["Identifier"]
            for page in cc.get_paginator("list_resources").paginate(TypeName="AWS::SQS::Queue")
            for d in page.get("ResourceDescriptions", [])
        ]
        if queue_url not in listed or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    assert queue_url not in listed, f"deleted queue {queue_url!r} is still listed by ListResources"

    # ...a mutation on the dead id is refused synchronously as ResourceNotFoundException...
    code, status, message = _error(
        lambda: cc.update_resource(
            TypeName="AWS::SQS::Queue",
            Identifier=queue_url,
            PatchDocument=json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 45}]),
        ),
        "cloudcontrol update_resource after delete_resource",
    )
    assert code == "ResourceNotFoundException", (
        f"UpdateResource on the deleted queue must be refused with ResourceNotFoundException, "
        f"got {code!r}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx from update_resource after delete, got {status!r}"
    message_head, _, request_id = message.partition(", RequestToken: ")
    expected_message = f"{create_event['TypeName']} Handler returned status FAILED: Resource of type '{create_event['TypeName']}' with identifier '{queue_url}' was not found. (HandlerErrorCode: NotFound"
    assert message_head == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)", request_id), f"unexpected request id in {message!r}"

    # ...and the underlying data plane is gone too (queue no longer exists for SQS itself).
    # SQS DeleteQueue takes up to 60 s, during which requests on the queue may still succeed.
    sqs_code, sqs_status, sqs_message = _await_sqs_error(
        ctx, lambda: sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1),
        "sqs receive_message after cloudcontrol delete_resource",
    )
    assert sqs_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected AWS.SimpleQueueService.NonExistentQueue from sqs receive_message after "
        f"cloudcontrol delete, got {sqs_code!r}"
    )
    assert isinstance(sqs_status, int) and 400 <= sqs_status < 500, f"expected HTTP 4xx from sqs receive_message after delete, got {sqs_status!r}"
    expected_message = "The specified queue does not exist."
    assert sqs_message == expected_message, f"expected the message {expected_message!r}, got {sqs_message!r}"


def _wait_for_progress(cc, request_token: str, timeout_s: float = 180.0, interval_s: float = 2.0) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state; last={last}")


def _get_properties(cc, type_name: str, identifier: str) -> dict:
    resp = cc.get_resource(TypeName=type_name, Identifier=identifier)
    return json.loads(resp["ResourceDescription"]["Properties"])


def _error(fn, description: str) -> tuple:
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected SUCCESS raises -- a target that
    still accepts the call is diverging from real AWS in the strongest possible way."""
    try:
        result = fn()
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return exc.response["Error"]["Code"], status, exc.response["Error"].get("Message") or ""
    raise AssertionError(f"{description}: expected a ClientError but the call succeeded and returned {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _await_sqs_error(ctx, fn, description: str, cap_s: float = 75.0) -> tuple:
    """Call fn() until it raises a ClientError; return its (code, HTTP status, message)."""
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + min(cap_s, budget_s)
    while True:
        try:
            result = fn()
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            return exc.response["Error"]["Code"], status, exc.response["Error"].get("Message") or ""
        if time.monotonic() >= deadline:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s wait for {description} to fail ended; not graded"
                )
            raise AssertionError(f"{description}: expected a ClientError but the call kept succeeding; last {result!r}")
        time.sleep(3.0)


def _best_effort_delete(cc, queue_url: str) -> None:
    try:
        resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
        _wait_for_progress(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
