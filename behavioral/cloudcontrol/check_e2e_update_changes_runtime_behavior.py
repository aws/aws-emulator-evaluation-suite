"""e2e-update-changes-runtime-behavior."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-update-changes-runtime-behavior"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


# timing:real-time — visibility: 2 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Lowering SQS VisibilityTimeout 120->2 via UpdateResource makes a received message reappear
    within 15s; after delete the queue name stops resolving and SendMessage is refused."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    queue_name = ctx.unique_name("sim2real-cc-updbeh-")
    desired_state = json.dumps(
        {
            "QueueName": queue_name,
            "VisibilityTimeout": 120,
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }
    )
    create_resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)
    create_event = _wait_for_progress(cc, create_resp["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", create_event
    queue_url = create_event["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(cc, queue_url))

    patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 2}])
    update_resp = cc.update_resource(
        TypeName="AWS::SQS::Queue", Identifier=queue_url, PatchDocument=patch
    )
    _wait_for_progress(cc, update_resp["ProgressEvent"]["RequestToken"])
    # Deliberately not asserting OperationStatus: the visibility timing below is the evidence.

    sqs.send_message(QueueUrl=queue_url, MessageBody="visibility-behavior-probe")
    first = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    assert len(first.get("Messages", [])) == 1, "expected the probe message to be receivable"

    # The message is now hidden. With the original 120s timeout it would stay hidden far
    # longer than this bounded poll; with the updated 2s timeout it must reappear quickly.
    reappeared = None
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        msgs = resp.get("Messages", [])
        if msgs and msgs[0]["Body"] == "visibility-behavior-probe":
            reappeared = msgs[0]
            break
        time.sleep(1)
    assert reappeared is not None, (
        "message did not become visible again within 15s; the updated VisibilityTimeout=2 "
        "does not appear to be honored by the queue's real runtime behavior"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=reappeared["ReceiptHandle"])

    delete_resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
    delete_event = _wait_for_progress(cc, delete_resp["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", delete_event

    # SQS's own DeleteQueue is eventually consistent -- the name can keep resolving for a
    # while after cloudcontrol reports the delete as SUCCESS -- so this is a bounded poll,
    # not a single read.
    not_found_codes = {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}
    not_found_deadline = time.monotonic() + 120
    while True:
        try:
            sqs.get_queue_url(QueueName=queue_name)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            assert code in not_found_codes, (
                f"expected a not-found code after delete, got {code!r} ({exc})"
            )
            message = exc.response.get("Error", {}).get("Message", "")
            assert message == "The specified queue does not exist.", message
            break
        if time.monotonic() >= not_found_deadline:
            raise AssertionError(
                f"get_queue_url({queue_name!r}) still resolves 120s after cloudcontrol "
                "delete_resource reported SUCCESS"
            )
        time.sleep(5)

    try:
        sqs.send_message(QueueUrl=queue_url, MessageBody="post-delete-should-fail")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        assert code in not_found_codes, (
            f"expected a not-found code sending to the deleted queue, got {code!r} ({exc})"
        )
        message = exc.response.get("Error", {}).get("Message", "")
        assert message == "The specified queue does not exist.", message
    else:
        raise AssertionError(
            f"send_message to {queue_url!r} unexpectedly succeeded after delete"
        )


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
