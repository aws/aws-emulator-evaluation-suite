"""numeric-precision-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "numeric-precision-round-trip"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A high-precision double property (CloudWatch Alarm Threshold) is persisted and
    returned through Cloud Control with no rounding or truncation."""
    cc = ctx.client("cloudcontrol")

    alarm_name = ctx.unique_name("sim2real-cc-numprec-")
    threshold = 63.256789123456
    desired_state = json.dumps(
        {
            "AlarmName": alarm_name,
            "ComparisonOperator": "GreaterThanThreshold",
            "EvaluationPeriods": 1,
            "MetricName": "CPUUtilization",
            "Namespace": "AWS/EC2",
            "Period": 60,
            "Statistic": "Average",
            "Threshold": threshold,
            "ActionsEnabled": False,
        }
    )
    create_resp = cc.create_resource(TypeName="AWS::CloudWatch::Alarm", DesiredState=desired_state)
    event = _wait_for_progress(cc, create_resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", event
    identifier = event["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(cc, identifier))

    props = _get_properties(cc, "AWS::CloudWatch::Alarm", identifier)
    assert props["Threshold"] == threshold, (
        f"expected exact threshold {threshold!r}, got {props['Threshold']!r} (precision lost)"
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


def _best_effort_delete(cc, identifier: str) -> None:
    try:
        resp = cc.delete_resource(TypeName="AWS::CloudWatch::Alarm", Identifier=identifier)
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
