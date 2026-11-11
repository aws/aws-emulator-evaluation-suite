"""long-running-request-timeout-yields-failed-status."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "long-running-request-timeout-yields-failed-status"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudcontrol"]

_TYPE_NAME = "AWS::CertificateManager::Certificate"
_TERMINAL = ("SUCCESS", "FAILED", "CANCEL_COMPLETE")
# A DNS-validated certificate for an uncontrolled domain reaches FAILED in about 45s (a fixed
# internal retry, not DNS timing); 180s leaves 4x headroom.
_TIMEOUT_S = 180.0


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResource for a DNS-validated ACM certificate on a domain the requester cannot
    validate ends FAILED with InvalidRequest and ACM's validation-failed message, not a timeout.
    """
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    # Positive control first, so a target that fails every create cannot pass.
    ctrl_name = ctx.unique_name("sim2real-cc-timeout-ctrl-")
    ctrl_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": ctrl_name})
    )
    ctrl_pe = _poll_terminal(cc, ctrl_resp["ProgressEvent"]["RequestToken"], timeout_s=90.0)
    assert ctrl_pe["OperationStatus"] == "SUCCESS", (
        f"positive control failed: cloudcontrol create_resource does not even succeed for a "
        f"plain SQS queue, so the ACM failure below proves nothing -- got {ctrl_pe}"
    )
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", ctrl_pe["Identifier"], teardown))

    domain = f"{ctx.unique_name('sim2real-cc-timeout-').lower()}.example.com"
    resp = cc.create_resource(
        TypeName=_TYPE_NAME,
        DesiredState=json.dumps({
            "DomainName": domain,
            "ValidationMethod": "DNS",
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }),
    )
    pe = _poll_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=_TIMEOUT_S)

    if pe.get("Identifier"):
        ctx.on_cleanup(lambda: _delete_resource(cc, _TYPE_NAME, pe["Identifier"], teardown))

    assert pe["OperationStatus"] == "FAILED", (
        f"expected the never-validated certificate create to terminate FAILED, got {pe}"
    )
    expected = ("InvalidRequest", "Invalid request provided: Certificate validation failed with status: FAILED")
    assert (pe.get("ErrorCode"), pe.get("StatusMessage")) == expected, (
        f"expected ErrorCode and StatusMessage {expected!r}, got full pe={pe}"
    )


def _poll_terminal(cc, token, timeout_s, interval_s=15.0):
    pe = None
    identifier = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pe = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        identifier = pe.get("Identifier") or identifier
        if pe["OperationStatus"] in _TERMINAL:
            return pe
        time.sleep(interval_s)
    raise AssertionError(
        f"request {token} never reached a terminal state within {timeout_s}s "
        f"(last={pe}, last known identifier={identifier})"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
