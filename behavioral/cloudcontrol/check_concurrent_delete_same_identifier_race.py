"""concurrent-delete-same-identifier-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-same-identifier-race"
GROUP = "concurrency"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of two simultaneous DeleteResource calls on one SQS queue exactly one succeeds; the other is
    refused with ConcurrentOperationException and an exact message or ends FAILED/NotFound, and
    GetResource and SQS then report the queue gone with exact messages."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-cc-race-")
    type_name = "AWS::SQS::Queue"

    create_resp = cc.create_resource(
        TypeName=type_name,
        DesiredState=json.dumps(
            {"QueueName": queue_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ),
    )
    create_token = create_resp["ProgressEvent"]["RequestToken"]
    teardown = _Teardown()
    ctx.on_cleanup(lambda: _cleanup_request(cc, type_name, create_token, teardown))
    create_final = _poll_request_status(cc, create_token, timeout_s=90)
    assert create_final["OperationStatus"] == "SUCCESS", create_final
    identifier = create_final["Identifier"]

    def _do_delete():
        return cc.delete_resource(TypeName=type_name, Identifier=identifier)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_do_delete) for _ in range(2)]
        outcomes = []
        for fut in futures:
            try:
                resp = fut.result()
                outcomes.append(("accepted", resp["ProgressEvent"]["RequestToken"]))
            except ClientError as exc:
                outcomes.append(
                    ("rejected", (exc.response["Error"]["Code"], exc.response["Error"]["Message"]))
                )

    accepted_tokens = [tok for kind, tok in outcomes if kind == "accepted"]
    rejected = [err for kind, err in outcomes if kind == "rejected"]
    rejected_codes = [code for code, _ in rejected]

    # Both requests must be accounted for -- accepted or synchronously rejected.
    assert len(accepted_tokens) + len(rejected_codes) == 2, outcomes

    # Any synchronous rejection must be the well-defined conflict code, never
    # an opaque/unclassified failure.
    for code in rejected_codes:
        assert code == "ConcurrentOperationException", f"unexpected rejection code: {code}"
    # A rejection names the accepted racer's RequestToken once that request is registered, so
    # either exact form is AWS's answer depending on how close the two calls land.
    concurrent = f"Concurrent operation found for resource {identifier}"
    expected_rejections = (concurrent, *(f"{concurrent} with RequestToken {t}" for t in accepted_tokens))
    for _, message in rejected:
        assert message in expected_rejections, (
            f"expected a rejection message in {expected_rejections!r}, got {message!r}"
        )

    finals = [_poll_request_status(cc, tok, timeout_s=90) for tok in accepted_tokens]
    success_finals = [f for f in finals if f["OperationStatus"] == "SUCCESS"]
    failed_finals = [f for f in finals if f["OperationStatus"] == "FAILED"]

    # Exactly one of the racers ever actually deletes the resource -- never zero
    # (both failed) and never two (double delete).
    assert len(success_finals) == 1, f"expected exactly 1 successful delete, got finals={finals}"
    for failed in failed_finals:
        # message varies: the losing racer's FAILED StatusMessage was never observed on AWS,
        # where the second delete is always refused synchronously instead.
        assert failed.get("ErrorCode") == "NotFound", f"unexpected terminal failure: {failed}"

    # The resource is genuinely gone -- confirms the single successful delete
    # took effect and there's no leftover from the losing racer.
    code, message = _client_error(lambda: cc.get_resource(TypeName=type_name, Identifier=identifier))
    assert code == "ResourceNotFoundException", f"expected queue gone, got error={code}"
    expected = _handler_not_found(type_name, identifier, message)
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Cloud Control's own index agreeing isn't enough -- confirm against the native
    # SQS API too, so a target that only clears its index (but leaves the queue) fails.
    native_code, native_message = _client_error(
        lambda: sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["All"])
    )
    assert native_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected native queue gone, got error={native_code}"
    )
    assert native_message == "The specified queue does not exist.", (
        f"expected SQS's NonExistentQueue message, got {native_message!r}"
    )


def _poll_request_status(cc, token, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach terminal state within {timeout_s}s: {last}")


def _client_error(fn):
    """The (code, message) of the ClientError fn() raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _handler_not_found(type_name, identifier, message):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return (
        f"{type_name} Handler returned status FAILED: Resource of type '{type_name}' with "
        f"identifier '{identifier}' was not found. (HandlerErrorCode: NotFound, RequestToken: {token})"
    )


#: Seconds every teardown of one run shares: the suite's 900 s cleanup budget less a 120 s margin.
_CLEANUP_S = 780.0


class _Teardown:
    """One deadline for all of a run's teardowns, started when the first of them runs."""

    def __init__(self) -> None:
        self._at = None

    def deadline(self) -> float:
        if self._at is None:
            self._at = time.monotonic() + _CLEANUP_S
        return self._at


def _request_outcome(cc, token: str, teardown) -> dict:
    """Poll GetResourceRequestStatus every 2 s until the request ends; return its ProgressEvent."""
    while True:
        event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if event["OperationStatus"] not in ("PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"):
            return event
        if time.monotonic() >= teardown.deadline():
            raise AssertionError(
                f"request {token} is still {event['OperationStatus']} at the cleanup deadline"
            )
        time.sleep(2)


def _delete_resource(cc, type_name: str, identifier: str, teardown) -> None:
    """DeleteResource and wait for its outcome; a NotFound answer means the resource is gone.

    ConcurrentOperationException and ResourceConflictException (another request holds the
    resource) are retried every 2 s to the shared cleanup deadline; anything else raises."""
    while True:
        try:
            resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConcurrentOperationException", "ResourceConflictException"):
                raise
            if time.monotonic() >= teardown.deadline():
                raise
            time.sleep(2)
    event = _request_outcome(cc, resp["ProgressEvent"]["RequestToken"], teardown)
    if event["OperationStatus"] == "FAILED" and event.get("ErrorCode") == "NotFound":
        return
    if event["OperationStatus"] != "SUCCESS":
        raise AssertionError(
            f"DeleteResource of {type_name} {identifier} ended {event['OperationStatus']}: {event}"
        )


def _cleanup_request(cc, type_name: str, token: str, teardown) -> None:
    """Wait for a create request to end, then delete the resource it made."""
    event = _request_outcome(cc, token, teardown)
    if event["OperationStatus"] == "SUCCESS":
        _delete_resource(cc, type_name, event["Identifier"], teardown)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
