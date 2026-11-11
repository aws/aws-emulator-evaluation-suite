"""invalid-schema-property-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-schema-property-rejected"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResource rejects a CloudWatch Alarm DesiredState whose numeric Threshold is a string
    with ValidationException and creates no alarm, while the same request correctly typed succeeds."""
    cc = ctx.client("cloudcontrol")
    cw = ctx.client("cloudwatch")

    bad_alarm_name = ctx.unique_name("sim2real-cc-badtype-")
    bad_desired_state = json.dumps(
        {
            "AlarmName": bad_alarm_name,
            "ComparisonOperator": "GreaterThanThreshold",
            "EvaluationPeriods": 1,
            "MetricName": "CPUUtilization",
            "Namespace": "AWS/EC2",
            "Period": 60,
            "Statistic": "Average",
            "Threshold": "not-a-number",
        }
    )
    code, message = _create_and_capture_failure(
        cc, "AWS::CloudWatch::Alarm", bad_desired_state
    )
    # Empirically verified against real AWS: a JSON-schema type mismatch (string where
    # the resource schema requires a number) is rejected with ValidationException.
    assert code == "ValidationException", (
        f"unexpected failure code for malformed Threshold: {code!r}"
    )
    assert message == "Model validation failed (#/Threshold: expected type: Number, found: String)", (
        f"the refusal must name the property and both JSON types, got {message!r}"
    )

    # Effect absent: the malformed alarm was never created.
    existing = cw.describe_alarms(AlarmNames=[bad_alarm_name]).get("MetricAlarms", [])
    assert existing == [], f"alarm with malformed Threshold was created anyway: {existing}"

    # Positive control: the same shape, correctly typed, succeeds.
    good_alarm_name = ctx.unique_name("sim2real-cc-goodtype-")
    good_desired_state = json.dumps(
        {
            "AlarmName": good_alarm_name,
            "ComparisonOperator": "GreaterThanThreshold",
            "EvaluationPeriods": 1,
            "MetricName": "CPUUtilization",
            "Namespace": "AWS/EC2",
            "Period": 60,
            "Statistic": "Average",
            "Threshold": 80.0,
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }
    )
    create_resp = cc.create_resource(TypeName="AWS::CloudWatch::Alarm", DesiredState=good_desired_state)
    event = _wait_for_progress(cc, create_resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", event
    identifier = event["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(cc, identifier))

    props = _get_properties(cc, "AWS::CloudWatch::Alarm", identifier)
    assert props["Threshold"] == 80.0

    # Terminal read at the native resource, not the Cloud Control proxy: CloudWatch's
    # own DescribeAlarms must agree that the alarm exists with the well-typed value.
    native_alarms = cw.describe_alarms(AlarmNames=[good_alarm_name]).get("MetricAlarms", [])
    assert len(native_alarms) == 1, f"expected exactly one native alarm, found {native_alarms}"
    assert native_alarms[0]["Threshold"] == 80.0, (
        f"native CloudWatch alarm has Threshold {native_alarms[0]['Threshold']!r}, expected 80.0"
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


def _get_properties(cc, type_name: str, identifier: str) -> dict:
    resp = cc.get_resource(TypeName=type_name, Identifier=identifier)
    return json.loads(resp["ResourceDescription"]["Properties"])


def _create_and_capture_failure(cc, type_name: str, desired_state: str) -> tuple[str, str]:
    """CreateResource may reject a malformed DesiredState synchronously (schema-level
    validation -> ClientError) or accept the request and fail it asynchronously
    (provider-level validation -> terminal FAILED ProgressEvent). Handle both and
    return the failure's (code, message); a request that succeeds raises."""
    try:
        create_resp = cc.create_resource(TypeName=type_name, DesiredState=desired_state)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    event = _wait_for_progress(cc, create_resp["ProgressEvent"]["RequestToken"])
    if event["OperationStatus"] == "SUCCESS":
        identifier = event.get("Identifier")
        if identifier:
            _best_effort_delete(cc, identifier)
        raise AssertionError(f"expected the malformed request to fail, but it succeeded: {event}")
    return event.get("ErrorCode"), event.get("StatusMessage")


def _best_effort_delete(cc, identifier: str) -> None:
    """Delete and wait; an already-gone alarm is fine, any other outcome raises."""
    try:
        resp = cc.delete_resource(TypeName="AWS::CloudWatch::Alarm", Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    final = _wait_for_progress(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60)
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise AssertionError(f"deleting {identifier} ended {final['OperationStatus']}: {final}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
