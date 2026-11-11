"""server-side-unique-request-token-per-operation."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-unique-request-token-per-operation"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientToken on an unrelated CreateResource is a ClientTokenConflictException that
    creates nothing: the token is an account-wide idempotency key, not per type. A fresh token
    gets its own RequestToken, which tracks only its own operation."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    shared_client_token = uuid.uuid4().hex

    queue_name = ctx.unique_name("sim2real-cc-tok-q-")
    create_q = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        ClientToken=shared_client_token,
        DesiredState=json.dumps({"QueueName": queue_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}),
    )
    token_q = create_q["ProgressEvent"]["RequestToken"]
    final_q = _poll_request_status(cc, token_q, timeout_s=90.0)
    assert final_q["OperationStatus"] == "SUCCESS", f"queue create failed: {final_q}"
    queue_url = final_q["Identifier"]
    ctx.on_cleanup(lambda: _best_effort(lambda: sqs.delete_queue(QueueUrl=queue_url)))

    topic_name = ctx.unique_name("sim2real-cc-tok-t-")
    topic_desired_state = json.dumps(
        {"TopicName": topic_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    )
    conflict_code = conflict_message = None
    try:
        cc.create_resource(
            TypeName="AWS::SNS::Topic",
            ClientToken=shared_client_token,  # same literal token, different type + payload
            DesiredState=topic_desired_state,
        )
    except ClientError as err:
        conflict_code = err.response["Error"]["Code"]
        conflict_message = err.response["Error"].get("Message")
    assert conflict_code == "ClientTokenConflictException", (
        "expected reusing the same ClientToken across an unrelated CreateResource call to be "
        f"rejected with ClientTokenConflictException, got {conflict_code!r}"
    )
    expected_conflict = (
        f"ClientToken {shared_client_token} is already associated with an existing operation "
        f"with RequestToken {token_q}"
    )
    assert conflict_message == expected_conflict, (
        f"expected ClientTokenConflictException message {expected_conflict!r}, got {conflict_message!r}"
    )

    # SNS topic ARNs are deterministic, so a read at SNS itself proves nothing was created.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    rejected_topic_arn = f"arn:aws:sns:{ctx.region}:{account_id}:{topic_name}"
    not_found_code = not_found_message = None
    try:
        sns.get_topic_attributes(TopicArn=rejected_topic_arn)
    except ClientError as err:
        not_found_code = err.response["Error"]["Code"]
        not_found_message = err.response["Error"].get("Message")
    assert not_found_code == "NotFound", (
        "expected the conflicting CreateResource to have created nothing, but reading "
        f"{rejected_topic_arn!r} at SNS directly did not report NotFound (got {not_found_code!r})"
    )
    assert not_found_message == "Topic does not exist", (
        f"unexpected SNS NotFound message: {not_found_message!r}"
    )

    create_t = cc.create_resource(
        TypeName="AWS::SNS::Topic",
        ClientToken=uuid.uuid4().hex,
        DesiredState=topic_desired_state,
    )
    token_t = create_t["ProgressEvent"]["RequestToken"]
    final_t = _poll_request_status(cc, token_t, timeout_s=90.0)
    assert final_t["OperationStatus"] == "SUCCESS", f"topic create failed: {final_t}"
    topic_arn = final_t["Identifier"]
    ctx.on_cleanup(lambda: _best_effort(lambda: sns.delete_topic(TopicArn=topic_arn)))

    assert token_q != token_t, "expected a distinct RequestToken per operation"

    assert final_q["TypeName"] == "AWS::SQS::Queue" and final_q["Identifier"] == queue_url
    assert final_t["TypeName"] == "AWS::SNS::Topic" and final_t["Identifier"] == topic_arn

    status_q = cc.get_resource_request_status(RequestToken=token_q)["ProgressEvent"]
    status_t = cc.get_resource_request_status(RequestToken=token_t)["ProgressEvent"]
    assert status_q["Identifier"] == queue_url and status_q["TypeName"] == "AWS::SQS::Queue"
    assert status_t["Identifier"] == topic_arn and status_t["TypeName"] == "AWS::SNS::Topic"



def _poll_request_status(cc: Any, token: str, *, timeout_s: float, interval_s: float = 2.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached a terminal state in {timeout_s}s: {last}")


def _best_effort(fn: Any) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "NotFound",
            "QueueDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
