"""numeric-precision-property-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "numeric-precision-property-round-trip"
GROUP = "representation"
SERVICES = ["cloudcontrol"]

_ALARM_NOT_FOUND = "AWS::CloudWatch::Alarm Handler returned status FAILED: Alarm does not exist"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Full float64 Threshold values (pi, e) survive CreateResource and UpdateResource unrounded via
    GetResource; after delete, GetResource and UpdateResource both fail ResourceNotFoundException."""
    cc = ctx.client("cloudcontrol")
    alarm_name = ctx.unique_name("sim2real-behav-cc-num-")
    initial_threshold = 3.141592653589793
    desired_state = json.dumps(
        {
            "AlarmName": alarm_name,
            "Namespace": "AWS/EC2",
            "MetricName": "CPUUtilization",
            "Statistic": "Average",
            "Period": 300,
            "EvaluationPeriods": 1,
            "ComparisonOperator": "GreaterThanThreshold",
            "Threshold": initial_threshold,
        }
    )
    resp = cc.create_resource(TypeName="AWS::CloudWatch::Alarm", DesiredState=desired_state)
    event = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", f"expected CreateResource to reach SUCCESS, got {event}"
    identifier = event["Identifier"]
    ctx.on_cleanup(lambda: _delete_and_wait(ctx, identifier, "AWS::CloudWatch::Alarm"))

    got = cc.get_resource(TypeName="AWS::CloudWatch::Alarm", Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert props["Threshold"] == initial_threshold, (
        f"expected Threshold {initial_threshold!r} to survive CreateResource+GetResource unchanged, "
        f"got {props['Threshold']!r}"
    )

    updated_threshold = 2.718281828459045
    patch = json.dumps([{"op": "replace", "path": "/Threshold", "value": updated_threshold}])
    upd_resp = cc.update_resource(
        TypeName="AWS::CloudWatch::Alarm", Identifier=identifier, PatchDocument=patch
    )
    upd_event = _wait_for_progress(ctx, upd_resp["ProgressEvent"]["RequestToken"])
    assert upd_event["OperationStatus"] == "SUCCESS", f"expected UpdateResource to reach SUCCESS, got {upd_event}"

    got2 = cc.get_resource(TypeName="AWS::CloudWatch::Alarm", Identifier=identifier)
    props2 = json.loads(got2["ResourceDescription"]["Properties"])
    assert props2["Threshold"] == updated_threshold, (
        f"expected Threshold {updated_threshold!r} to survive UpdateResource+GetResource unchanged, "
        f"got {props2['Threshold']!r}"
    )

    _delete_and_wait(ctx, identifier, "AWS::CloudWatch::Alarm")

    get_after_delete_code, get_after_delete_message = _expect_failure(
        lambda: cc.get_resource(TypeName="AWS::CloudWatch::Alarm", Identifier=identifier)
    )
    assert get_after_delete_code == "ResourceNotFoundException", (
        f"expected GetResource on a deleted alarm to raise ResourceNotFoundException, "
        f"got {get_after_delete_code!r}"
    )
    expected = _handler_not_found(get_after_delete_message, _ALARM_NOT_FOUND)
    assert get_after_delete_message == expected, f"expected message {expected!r}, got {get_after_delete_message!r}"

    dead_patch = json.dumps([{"op": "replace", "path": "/Threshold", "value": updated_threshold}])
    update_after_delete_code, update_after_delete_message = _expect_failure(
        lambda: _update_and_settle(ctx, identifier, dead_patch)
    )
    assert update_after_delete_code == "ResourceNotFoundException", (
        f"expected UpdateResource on a deleted alarm to be refused with ResourceNotFoundException, "
        f"got {update_after_delete_code!r}"
    )
    expected = _handler_not_found(update_after_delete_message, _ALARM_NOT_FOUND)
    assert update_after_delete_message == expected, (
        f"expected message {expected!r}, got {update_after_delete_message!r}"
    )


def _expect_failure(fn):
    """Call fn(); return the botocore Error.Code and Error.Message. Raise if fn unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result}")


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _update_and_settle(ctx, identifier, patch_document):
    """UpdateResource on CloudControl can reject an unknown identifier either synchronously or by
    landing the async request in a terminal FAILED progress event; surface both as a raised
    ClientError-shaped code so _expect_failure has one call shape to check."""
    cc = ctx.client("cloudcontrol")
    resp = cc.update_resource(
        TypeName="AWS::CloudWatch::Alarm", Identifier=identifier, PatchDocument=patch_document
    )
    event = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    if event["OperationStatus"] == "FAILED":
        raise ClientError(
            {"Error": {"Code": event.get("ErrorCode", "Unknown"), "Message": event.get("StatusMessage", "")}},
            "UpdateResource",
        )
    return event


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


def _delete_and_wait(ctx, identifier, type_name):
    cc = ctx.client("cloudcontrol")
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    final = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise AssertionError(f"deleting {identifier} ended {final['OperationStatus']}: {final}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
