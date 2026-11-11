"""server-side-unique-request-token-per-operation-dup-removed."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-unique-request-token-per-operation-dup-removed"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientToken for a CreateResource of another type fails with
    ClientTokenConflictException and creates nothing; with a fresh ClientToken each operation gets
    a distinct server-minted RequestToken that resolves to its own resource."""
    cc = ctx.client("cloudcontrol")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    shared_client_token = ctx.unique_name("sim2real-cc-shared-tok2-")
    queue_name = ctx.unique_name("sim2real-cc-tok2-q-")
    topic_name = ctx.unique_name("sim2real-cc-tok2-t-")
    topic_arn = f"arn:aws:sns:{ctx.region}:{account_id}:{topic_name}"

    resp1 = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        ClientToken=shared_client_token,
        DesiredState=json.dumps(
            {"QueueName": queue_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ),
    )
    token1 = resp1["ProgressEvent"]["RequestToken"]
    final1 = _poll_progress(ctx, cc, token1)
    assert final1["OperationStatus"] == "SUCCESS", final1
    identifier1 = final1["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(ctx, cc, "AWS::SQS::Queue", identifier1))

    # Reusing the exact same ClientToken for a totally different resource type/operation, even
    # after the first request has already fully completed, is rejected up front -- ClientToken
    # conflicts are enforced regardless of resource type or in-flight overlap.
    conflict_code = conflict_message = None
    try:
        cc.create_resource(
            TypeName="AWS::SNS::Topic",
            ClientToken=shared_client_token,
            DesiredState=json.dumps(
                {"TopicName": topic_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
            ),
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
        f"with RequestToken {token1}"
    )
    assert conflict_message == expected_conflict, (
        f"expected ClientTokenConflictException message {expected_conflict!r}, got {conflict_message!r}"
    )

    # The conflicting call was never accepted, so it must have had no effect: the topic it
    # would have created is absent from an independent read, not merely "not returned yet".
    # message varies: Cloud Control embeds the server-minted RequestToken of its own handler
    # invocation, which no response returns.
    not_found_code = None
    try:
        cc.get_resource(TypeName="AWS::SNS::Topic", Identifier=topic_arn)
    except ClientError as err:
        not_found_code = err.response["Error"]["Code"]
    assert not_found_code == "ResourceNotFoundException", (
        "the rejected CreateResource call must not have created the topic, expected "
        f"ResourceNotFoundException on an independent read, got {not_found_code!r}"
    )

    # A genuinely distinct ClientToken for the second call succeeds normally.
    resp2 = cc.create_resource(
        TypeName="AWS::SNS::Topic",
        ClientToken=ctx.unique_name("sim2real-cc-tok2-t-client-"),
        DesiredState=json.dumps(
            {"TopicName": topic_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ),
    )
    token2 = resp2["ProgressEvent"]["RequestToken"]
    final2 = _poll_progress(ctx, cc, token2)
    assert final2["OperationStatus"] == "SUCCESS", final2
    identifier2 = final2["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(ctx, cc, "AWS::SNS::Topic", identifier2))

    assert token1 != token2, "server reused the same RequestToken across two distinct operations"
    assert token1 != shared_client_token and token2 != shared_client_token, (
        "RequestToken must be server-minted, not an echo of the caller-supplied ClientToken"
    )

    status1 = cc.get_resource_request_status(RequestToken=token1)["ProgressEvent"]
    status2 = cc.get_resource_request_status(RequestToken=token2)["ProgressEvent"]
    assert status1["TypeName"] == "AWS::SQS::Queue" and status1["Identifier"] == identifier1, (
        f"token1 must resolve to its own queue operation, got {status1}"
    )
    assert status2["TypeName"] == "AWS::SNS::Topic" and status2["Identifier"] == identifier2, (
        f"token2 must resolve to its own topic operation, got {status2}"
    )


def _poll_progress(ctx: Any, cc: Any, token: str, timeout_s: float = 120.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"operation did not reach a terminal state within {timeout_s}s: {last}")


def _delete_resource(ctx: Any, cc: Any, type_name: str, identifier: str) -> None:
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _poll_progress(ctx, cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60.0)
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
