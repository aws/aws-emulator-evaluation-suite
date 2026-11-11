"""timestamp-property-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "timestamp-property-preserved"
GROUP = "representation"
SERVICES = ["cloudcontrol"]
MW_TYPE = "AWS::SSM::MaintenanceWindow"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ISO-8601 timestamp property (SSM MaintenanceWindow StartDate) retains its exact
    sub-second precision and non-UTC timezone offset across CreateResource and GetResource,
    and DeleteResource leaves the identifier unreadable through the same GetResource call."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-ts-")
    start_date = "2030-06-15T10:30:00.123456+05:30"

    desired_state = json.dumps(
        {
            "Name": name,
            "Schedule": "rate(1 day)",
            "Duration": 2,
            "Cutoff": 1,
            "AllowUnassociatedTargets": False,
            "StartDate": start_date,
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }
    )
    create = cc.create_resource(TypeName=MW_TYPE, DesiredState=desired_state)
    pe = _wait_for_operation(ctx, create["ProgressEvent"]["RequestToken"])
    identifier = pe["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(ctx, MW_TYPE, identifier))

    got = cc.get_resource(TypeName=MW_TYPE, Identifier=identifier)
    properties = json.loads(got["ResourceDescription"]["Properties"])
    assert properties["StartDate"] == start_date, (
        f"StartDate drifted: got {properties['StartDate']!r}, expected {start_date!r}"
    )

    delete = cc.delete_resource(TypeName=MW_TYPE, Identifier=identifier)
    delete_event = _wait_for_operation(ctx, delete["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", f"delete did not succeed: {delete_event!r}"

    code, message = _error_code(lambda: cc.get_resource(TypeName=MW_TYPE, Identifier=identifier))
    assert code == "ResourceNotFoundException", (
        f"GetResource after DeleteResource raised {code!r}, so the window is still readable"
    )
    assert _handler_not_found(
        message,
        f"{MW_TYPE} Handler returned status FAILED: Resource of type '{MW_TYPE}' "
        f"with identifier '{identifier}' was not found.",
    ), message


def _wait_for_operation(ctx, request_token, timeout_s=180.0, interval_s=2.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=request_token)
        pe = resp["ProgressEvent"]
        last = pe
        status = pe["OperationStatus"]
        if status == "SUCCESS":
            return pe
        if status in ("FAILED", "CANCEL_COMPLETE"):
            raise AssertionError(
                f"cloudcontrol operation ended in {status}: "
                f"{pe.get('StatusMessage')} / {pe.get('ErrorCode')}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"cloudcontrol operation did not reach terminal state within {timeout_s}s: {last}")


def _error_code(fn):
    """The AWS error code and message raised by fn(). Raises if the call unexpectedly SUCCEEDS -- returning a
    falsy sentinel there would turn the strongest possible signal into a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _handler_not_found(message, detail):
    """Whether message is the handler's NotFound refusal; its trailing RequestToken is server-chosen."""
    prefix = f"{detail} (HandlerErrorCode: NotFound, RequestToken: "
    return message.startswith(prefix) and message.endswith(")")


def _delete_resource(ctx, type_name, identifier):
    """Best-effort safety net: the check's own body already deletes and asserts the delete, so
    this only fires if an earlier assertion aborted the run before that point."""
    cc = ctx.client("cloudcontrol")
    try:
        delete = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise
        return
    token = delete["ProgressEvent"]["RequestToken"]
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        pe = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if pe["OperationStatus"] == "SUCCESS":
            return
        if pe["OperationStatus"] in ("FAILED", "CANCEL_COMPLETE"):
            # A window the body already deleted answers NotFound; anything else is a leak.
            assert pe.get("ErrorCode") == "NotFound", f"teardown delete of {identifier} failed: {pe}"
            return
        time.sleep(2.0)
    raise AssertionError(f"teardown delete of {identifier} did not terminate within 120s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
