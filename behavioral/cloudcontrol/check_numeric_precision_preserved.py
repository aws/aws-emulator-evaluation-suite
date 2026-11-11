"""numeric-precision-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AWS::CloudWatch::Alarm Threshold of 123456789.123456 set via CreateResource comes back
    unrounded from both GetResource and native CloudWatch DescribeAlarms."""
    cc = ctx.client("cloudcontrol")
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-numeric-")
    # a decimal literal with a large integer part and 6 fractional digits: well within
    # IEEE-754 double precision (~15-17 significant digits), but well past 2 decimal places.
    threshold_literal = "123456789.123456"
    desired_state = (
        '{"AlarmName": %s, "ComparisonOperator": "GreaterThanThreshold", '
        '"EvaluationPeriods": 1, "MetricName": "CPUUtilization", "Namespace": "AWS/EC2", '
        '"Period": 60, "Statistic": "Average", "Threshold": %s}'
        % (json.dumps(alarm_name), threshold_literal)
    )

    create = cc.create_resource(TypeName="AWS::CloudWatch::Alarm", DesiredState=desired_state)
    pe = _wait_for_operation(ctx, create["ProgressEvent"]["RequestToken"])
    identifier = pe["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(ctx, "AWS::CloudWatch::Alarm", identifier))

    got = cc.get_resource(TypeName="AWS::CloudWatch::Alarm", Identifier=identifier)
    properties = json.loads(got["ResourceDescription"]["Properties"])
    returned_threshold = properties["Threshold"]
    expected = float(threshold_literal)
    assert returned_threshold == expected, (
        f"Threshold precision drifted: got {returned_threshold!r}, expected {expected!r}"
    )

    alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(alarms) == 1, (
        f"expected exactly one native CloudWatch alarm named {alarm_name!r}, found {len(alarms)}"
    )
    native_threshold = alarms[0]["Threshold"]
    assert native_threshold == expected, (
        f"native CloudWatch DescribeAlarms reports Threshold {native_threshold!r}, but Cloud "
        f"Control's GetResource reported {returned_threshold!r} (expected {expected!r}): the two "
        "services disagree about the same resource's precision"
    )


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


def _delete_resource(ctx, type_name, identifier):
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
    _wait_for_operation(ctx, delete["ProgressEvent"]["RequestToken"], timeout_s=120.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
