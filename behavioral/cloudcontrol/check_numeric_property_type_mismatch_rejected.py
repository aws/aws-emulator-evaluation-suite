"""numeric-property-type-mismatch-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "numeric-property-type-mismatch-rejected"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DesiredState that supplies a string where AWS::CloudWatch::Alarm's Threshold
    schema requires a Number is rejected (ValidationException), the alarm is never
    created, and a same-shaped, well-typed alarm still succeeds in the same run."""
    cc = ctx.client("cloudcontrol")
    cw = ctx.client("cloudwatch")
    bad_alarm_name = ctx.unique_name("sim2real-behav-badnum-")
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

    # The registry schema types Threshold as a Number, so CreateResource refuses the request
    # synchronously, before any handler runs.
    code, message = _error(lambda: cc.create_resource(
        TypeName="AWS::CloudWatch::Alarm", DesiredState=bad_desired_state
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "Model validation failed (#/Threshold: expected type: Number, found: String)"
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # (b) effect absent: the malformed alarm must never have been created. Checked through
    # CloudControl's own index AND through the native CloudWatch API at the destination --
    # SERVICES declares both.
    # message varies: Cloud Control embeds the RequestToken of its own internal read in the
    # NotFound message, a token the caller never sees, so only the code is graded.
    get_code, _ = _error(lambda: cc.get_resource(
        TypeName="AWS::CloudWatch::Alarm", Identifier=bad_alarm_name
    ))
    assert get_code == "ResourceNotFoundException", (
        f"expected the malformed alarm to not exist, get_resource returned code {get_code!r}"
    )
    native = cw.describe_alarms(AlarmNames=[bad_alarm_name]).get("MetricAlarms", [])
    assert native == [], f"malformed alarm visible via native DescribeAlarms: {native}"

    # (c) positive control: a well-typed alarm with the same shape succeeds.
    good_alarm_name = ctx.unique_name("sim2real-behav-goodnum-")
    good_desired_state = json.dumps(
        {
            "AlarmName": good_alarm_name,
            "ComparisonOperator": "GreaterThanThreshold",
            "EvaluationPeriods": 1,
            "MetricName": "CPUUtilization",
            "Namespace": "AWS/EC2",
            "Period": 60,
            "Statistic": "Average",
            "Threshold": 42.5,
        }
    )
    create = cc.create_resource(TypeName="AWS::CloudWatch::Alarm", DesiredState=good_desired_state)
    pe_good = _wait_for_operation(ctx, create["ProgressEvent"]["RequestToken"])
    good_identifier = pe_good["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(ctx, "AWS::CloudWatch::Alarm", good_identifier))

    got = cc.get_resource(TypeName="AWS::CloudWatch::Alarm", Identifier=good_identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert props["Threshold"] == 42.5, f"expected Threshold 42.5, got {props.get('Threshold')!r}"

    native_good = cw.describe_alarms(AlarmNames=[good_alarm_name]).get("MetricAlarms", [])
    assert len(native_good) == 1, f"expected exactly one native alarm, got {native_good}"
    assert native_good[0]["Threshold"] == 42.5, (
        f"native DescribeAlarms disagrees with CloudControl on Threshold: {native_good[0]}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """The (code, message) of the ClientError fn() raises. Raises if the call SUCCEEDS."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


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
