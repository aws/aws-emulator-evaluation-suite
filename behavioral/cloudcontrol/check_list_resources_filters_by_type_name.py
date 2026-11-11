"""list-resources-filters-by-type-name."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resources-filters-by-type-name"
GROUP = "representation"
SERVICES = ["cloudcontrol"]

_SNS_TOPIC = "AWS::SNS::Topic"
_SQS_QUEUE = "AWS::SQS::Queue"

# The SQS create/update/delete handlers in Cloud Control perform ready-state
# stabilization checks and re-invoke themselves (observed RetryAfter = +60s), so
# SQS operations routinely need far more than the default 60s budget.
_SQS_TIMEOUT = 300.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResources for AWS::SNS::Topic lists the created topic and not the created queue, and for
    AWS::SQS::Queue the reverse; once both are deleted, GetResource answers ResourceNotFoundException
    with each handler's not-found message."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    name_topic = ctx.unique_name("sim2real-behav-cc-topic-")
    name_queue = ctx.unique_name("sim2real-behav-cc-queue-")
    topic_final = _create_and_wait(ctx, cc, _SNS_TOPIC, {"TopicName": name_topic}, teardown=teardown)
    queue_final = _create_and_wait(
        ctx, cc, _SQS_QUEUE, {"QueueName": name_queue}, timeout_s=_SQS_TIMEOUT, teardown=teardown
    )
    assert topic_final["OperationStatus"] == "SUCCESS", topic_final
    assert queue_final["OperationStatus"] == "SUCCESS", queue_final

    topic_ids = _poll_until(
        lambda: _list_identifiers(cc, _SNS_TOPIC),
        lambda ids: topic_final["Identifier"] in ids,
        timeout_s=60,
        interval_s=2,
        description="the created topic to appear in ListResources",
    )
    queue_ids = _poll_until(
        lambda: _list_identifiers(cc, _SQS_QUEUE),
        lambda ids: queue_final["Identifier"] in ids,
        timeout_s=90,
        interval_s=2,
        description="the created queue to appear in ListResources",
    )

    assert topic_final["Identifier"] in topic_ids, (topic_final["Identifier"], topic_ids)
    assert topic_final["Identifier"] not in queue_ids, (
        f"topic identifier {topic_final['Identifier']!r} leaked into the queue-typed listing: {queue_ids}"
    )
    assert queue_final["Identifier"] in queue_ids, (queue_final["Identifier"], queue_ids)
    assert queue_final["Identifier"] not in topic_ids, (
        f"queue identifier {queue_final['Identifier']!r} leaked into the topic-typed listing: {topic_ids}"
    )

    topic_delete = _delete_and_wait(cc, _SNS_TOPIC, topic_final["Identifier"])
    assert topic_delete["OperationStatus"] == "SUCCESS", f"topic delete did not succeed: {topic_delete}"
    queue_delete = _delete_and_wait(
        cc, _SQS_QUEUE, queue_final["Identifier"], timeout_s=_SQS_TIMEOUT
    )
    assert queue_delete["OperationStatus"] == "SUCCESS", f"queue delete did not succeed: {queue_delete}"

    # Each message carries server-chosen ids; the helpers read them back and rebuild the rest exactly.
    topic_code, topic_message = _error_code(
        lambda: cc.get_resource(TypeName=_SNS_TOPIC, Identifier=topic_final["Identifier"])
    )
    assert topic_code == "ResourceNotFoundException", f"expected ResourceNotFoundException for deleted topic, got {topic_code}"
    expected = _sns_topic_not_found(topic_message)
    assert topic_message == expected, f"expected message {expected!r}, got {topic_message!r}"
    queue_code, queue_message = _error_code(
        lambda: cc.get_resource(TypeName=_SQS_QUEUE, Identifier=queue_final["Identifier"])
    )
    assert queue_code == "ResourceNotFoundException", f"expected ResourceNotFoundException for deleted queue, got {queue_code}"
    expected = _handler_not_found(queue_message, _queue_not_found_detail(queue_final["Identifier"]))
    assert queue_message == expected, f"expected message {expected!r}, got {queue_message!r}"


_TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError("expected a ClientError, the call unexpectedly succeeded")


def _sns_topic_not_found(message):
    """The SNS handler's NotFound text; its request ids and attempt count vary per call, so they are read back."""
    found = re.search(r"Request ID: ([^)]*)\) \(SDK Attempt Count: (\d+)\) .*RequestToken: ([^)]*)\)$", message)
    request_id, attempts, token = found.groups() if found else ("<id>", "<n>", "<token>")
    return (
        "AWS::SNS::Topic Handler returned status FAILED: Topic does not exist (Service: Sns, Status Code: 404, "
        f"Request ID: {request_id}) (SDK Attempt Count: {attempts}) (HandlerErrorCode: NotFound, RequestToken: {token})"
    )


#: A RequestToken: a lowercase UUID.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken (a UUID) is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    token = token if re.fullmatch(_UUID, token) else "<a UUID>"
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _queue_not_found_detail(queue_url):
    return (
        "AWS::SQS::Queue Handler returned status FAILED: Resource of type 'AWS::SQS::Queue' "
        f"with identifier '{queue_url}' was not found."
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_for_request(cc, request_token: str, timeout_s: float = 60, interval_s: float = 2) -> dict:
    """Poll GetResourceRequestStatus until a terminal OperationStatus is reached."""

    def probe():
        return cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]

    return _poll_until(
        probe,
        lambda ev: ev.get("OperationStatus") in _TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"request {request_token} to reach a terminal state",
    )


def _create_and_wait(ctx, cc, type_name: str, desired_state: dict, timeout_s: float = 60, *, teardown) -> dict:
    """CreateResource + poll to terminal; registers teardown for a successful create."""
    resp = cc.create_resource(TypeName=type_name, DesiredState=json.dumps(desired_state))
    final = _wait_for_request(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=timeout_s)
    if final.get("OperationStatus") == "SUCCESS" and final.get("Identifier"):
        identifier = final["Identifier"]
        ctx.on_cleanup(lambda: _delete_resource(cc, type_name, identifier, teardown))
    return final


def _delete_and_wait(cc, type_name: str, identifier: str, timeout_s: float = 60) -> dict:
    resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    return _wait_for_request(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=timeout_s)


def _list_identifiers(cc, type_name: str, **kwargs) -> list[str]:
    identifiers: list[str] = []
    call_kwargs = dict(TypeName=type_name, **kwargs)
    while True:
        resp = cc.list_resources(**call_kwargs)
        for desc in resp.get("ResourceDescriptions", []):
            identifiers.append(desc["Identifier"])
        next_token = resp.get("NextToken")
        if not next_token:
            break
        call_kwargs["NextToken"] = next_token
    return identifiers


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
