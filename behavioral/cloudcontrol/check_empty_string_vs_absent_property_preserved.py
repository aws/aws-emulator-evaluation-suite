"""empty-string-vs-absent-property-preserved."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-string-vs-absent-property-preserved"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A queue tag written with an empty-string value reads back present with value "", while a queue
    created without that tag reads back without the key, so "present but empty" and "absent" stay
    distinct; the second queue's delete succeeds and GetResource then answers ResourceNotFoundException."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    name_empty = ctx.unique_name("sim2real-behav-cc-emptytag-")
    name_absent = ctx.unique_name("sim2real-behav-cc-absenttag-")

    resp_empty = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": name_empty, "Tags": [{"Key": "probe", "Value": ""}]}),
    )
    event_empty = _wait_for_progress(ctx, resp_empty["ProgressEvent"]["RequestToken"])
    assert event_empty["OperationStatus"] == "SUCCESS", event_empty
    id_empty = event_empty["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", id_empty, teardown))

    resp_absent = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": name_absent})
    )
    event_absent = _wait_for_progress(ctx, resp_absent["ProgressEvent"]["RequestToken"])
    assert event_absent["OperationStatus"] == "SUCCESS", event_absent
    id_absent = event_absent["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", id_absent, teardown))

    props_empty = json.loads(
        cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=id_empty)["ResourceDescription"]["Properties"]
    )
    props_absent = json.loads(
        cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=id_absent)["ResourceDescription"]["Properties"]
    )

    tags_empty = {t["Key"]: t["Value"] for t in props_empty.get("Tags", [])}
    tags_absent = {t["Key"]: t["Value"] for t in props_absent.get("Tags", [])}

    assert tags_empty.get("probe") == "", (
        f"expected tag 'probe' present with value '', got {tags_empty.get('probe')!r}"
    )
    assert "probe" not in tags_absent, (
        f"expected tag 'probe' entirely absent, got value {tags_absent.get('probe')!r}"
    )

    # The delete takes effect, shown by an independent read. A repeated DeleteResource is not
    # asserted to fail: AWS accepts a same-window repeat delete of an SQS queue without raising.
    delete_resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=id_absent)
    delete_event = _wait_for_progress(ctx, delete_resp["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", delete_event

    get_code, get_message = _error_code(lambda: cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=id_absent))
    assert get_code == "ResourceNotFoundException", (
        f"expected GetResource on the deleted queue to raise ResourceNotFoundException, got {get_code!r}"
    )
    expected = _handler_not_found(get_message, _queue_not_found_detail(id_absent))
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError, call succeeded")


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


def _wait_for_progress(ctx, request_token, timeout_s=180.0, interval_s=2.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    event = None
    while time.monotonic() < deadline:
        event = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if event["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return event
        time.sleep(interval_s)
    raise AssertionError(f"operation did not stabilize within {timeout_s}s, last event={event}")


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
