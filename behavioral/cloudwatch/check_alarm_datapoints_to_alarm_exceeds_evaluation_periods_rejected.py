"""alarm-datapoints-to-alarm-exceeds-evaluation-periods-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alarm-datapoints-to-alarm-exceeds-evaluation-periods-rejected"
GROUP = 'alarms'
SERVICES = ['cloudwatch']


# ===== helpers =====
def _error(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    return None


# The verbatim message real AWS returns for a violated M-of-N relation. Asserting it stops an
# unrelated ValidationError (a bad Statistic, a bad Period) from satisfying these legs.
_MOFN_MESSAGE = "DatapointsToAlarm must be less than or equal to EvaluationPeriods"


def _swallow(fn):
    """Run a cleanup callable, ignoring AWS-side errors."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricAlarm refuses DatapointsToAlarm > EvaluationPeriods as a relation (M == N accepted,
    M == N+1 refused at three N) without touching the existing alarm, and round-trips DatapointsToAlarm
    and every TreatMissingData value: a dropped field silently changes when an alarm pages."""
    cw = ctx.client("cloudwatch")
    alarm = ctx.unique_name("sim2real-behav-cwprobe-alarm-mofn-")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-mofn-")

    base = dict(
        AlarmName=alarm,
        Namespace=ns,
        MetricName="Errors",
        Statistic="Sum",
        Period=60,
        Threshold=5.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def describe():
        alarms = cw.describe_alarms(AlarmNames=[alarm], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
        assert len(alarms) == 1, f"expected exactly one alarm named {alarm}, got {alarms}"
        return alarms[0]

    # --- Positive: a valid 2-of-3 window round-trips ---
    cw.put_metric_alarm(EvaluationPeriods=3, DatapointsToAlarm=2, TreatMissingData="notBreaching", **base)
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[alarm])))

    a = describe()
    assert a["EvaluationPeriods"] == 3, f"expected EvaluationPeriods=3, got {a.get('EvaluationPeriods')}"
    assert a["DatapointsToAlarm"] == 2, (
        f"DatapointsToAlarm must round-trip as 2 -- an emulator that drops it turns a 2-of-3 alarm "
        f"into a 3-of-3 alarm; got {a.get('DatapointsToAlarm')}"
    )
    assert a["TreatMissingData"] == "notBreaching", (
        f"TreatMissingData must round-trip verbatim, got {a.get('TreatMissingData')!r}"
    )

    # --- Negative 1: M > N on CREATE is rejected and creates nothing ---
    other = ctx.unique_name("sim2real-behav-cwprobe-alarm-mofn-bad-")
    bad_create = dict(base)
    bad_create["AlarmName"] = other
    error = _error(lambda: cw.put_metric_alarm(EvaluationPeriods=3, DatapointsToAlarm=4, **bad_create))
    assert error is not None, (
        "DatapointsToAlarm=4 with EvaluationPeriods=3 is an impossible window and must be rejected"
    )
    assert error.get("Code") == "ValidationError", (
        f"the M-of-N relation is refused with ValidationError, got {error.get('Code')!r}"
    )
    assert error.get("Message") == _MOFN_MESSAGE, (
        f"the refusal must name the violated relation, got {error.get('Message')!r}"
    )
    leaked = cw.describe_alarms(AlarmNames=[other])
    assert leaked["MetricAlarms"] == [] and leaked.get("CompositeAlarms", []) == [], (
        f"the rejected PutMetricAlarm must not have created {other}; got {leaked}"
    )

    # --- Negative 2: the same bad relation as an UPDATE leaves the alarm unchanged ---
    error = _error(lambda: cw.put_metric_alarm(EvaluationPeriods=3, DatapointsToAlarm=4, **base))
    assert error is not None, "the same impossible window must be rejected when updating"
    assert error.get("Code") == "ValidationError", error
    assert error.get("Message") == _MOFN_MESSAGE, error
    after = describe()
    assert after["DatapointsToAlarm"] == 2 and after["EvaluationPeriods"] == 3, (
        f"PutMetricAlarm is a full replace, so a REJECTED update must leave the stored config at "
        f"2-of-3 with no partial write; got DatapointsToAlarm={after.get('DatapointsToAlarm')}, "
        f"EvaluationPeriods={after.get('EvaluationPeriods')}"
    )
    assert after["TreatMissingData"] == "notBreaching", (
        f"the rejected update must not have cleared TreatMissingData; got {after.get('TreatMissingData')!r}"
    )

    # --- Negative 3: an unmodeled TreatMissingData value is rejected ---
    error = _error(lambda: cw.put_metric_alarm(
        EvaluationPeriods=3, DatapointsToAlarm=2, TreatMissingData="ignoreEverything", **base
    ))
    assert error is not None, (
        "TreatMissingData accepts only missing/notBreaching/breaching/ignore, so an unknown "
        "value must be rejected rather than stored"
    )
    assert error.get("Code") == "ValidationError", error
    assert error.get("Message") == (
        "The value ignoreEverything is not supported for TreatMissingData parameter. "
        "Supported values are [breaching, notBreaching, ignore, missing]."
    ), f"the refusal must enumerate the accepted values, got {error.get('Message')!r}"
    assert describe()["TreatMissingData"] == "notBreaching", (
        "the rejected TreatMissingData value must not have been persisted"
    )

    # --- Negative 4: M-of-N is a RELATION, checked at the boundary in both directions ---
    # M == N is the tightest LEGAL window ("all N of N") and must be accepted; M == N+1 is
    # illegal at every N, so the validation cannot be a hard-coded comparison against one
    # number. DatapointsToAlarm=0 is deliberately NOT asserted: DatapointsToAlarm carries
    # {min: 1} and botocore's VALIDATED_METADATA_ATTRS includes 'min', so 0 is stopped
    # client-side with ParamValidationError and never reaches CloudWatch — it discriminates
    # nothing between real AWS and an emulator.
    for periods in (1, 3, 5):
        error = _error(lambda: cw.put_metric_alarm(
            EvaluationPeriods=periods, DatapointsToAlarm=periods + 1, **base
        ))
        assert error is not None, (
            f"DatapointsToAlarm={periods + 1} with EvaluationPeriods={periods} is an impossible "
            f"window and must be rejected"
        )
        assert error.get("Code") == "ValidationError", (periods, error)
        assert error.get("Message") == _MOFN_MESSAGE, (periods, error)
        # Effect absent at every N: the stored window is still the 2-of-3 from the positive leg.
        rejected_state = describe()
        assert rejected_state["DatapointsToAlarm"] == 2, (periods, rejected_state)
        assert rejected_state["EvaluationPeriods"] == 3, (periods, rejected_state)

    for periods in (1, 3, 5):
        cw.put_metric_alarm(EvaluationPeriods=periods, DatapointsToAlarm=periods, **base)
        equal = describe()
        assert equal["EvaluationPeriods"] == periods, (periods, equal)
        assert equal["DatapointsToAlarm"] == periods, (
            f"M == N is the tightest legal window ('all {periods} of {periods}') and must be "
            f"accepted and stored, got {equal.get('DatapointsToAlarm')}"
        )

    # --- Control: every remaining TreatMissingData value updates cleanly ---
    for value in ("missing", "breaching", "ignore"):
        cw.put_metric_alarm(EvaluationPeriods=5, DatapointsToAlarm=3, TreatMissingData=value, **base)
        got = describe()
        assert got["TreatMissingData"] == value, (
            f"expected TreatMissingData={value!r} after the update, got {got.get('TreatMissingData')!r}"
        )
        assert got["DatapointsToAlarm"] == 3 and got["EvaluationPeriods"] == 5, (
            f"expected the valid 3-of-5 window to be stored, got {got}"
        )

    # Omitting TreatMissingData on a full replace resets it to the documented default.
    cw.put_metric_alarm(EvaluationPeriods=5, DatapointsToAlarm=3, **base)
    final = describe()
    assert final.get("TreatMissingData", "missing") == "missing", (
        f"omitting TreatMissingData on a full-replace PutMetricAlarm must fall back to the default "
        f"'missing' behaviour, not retain the previous 'ignore'; got {final.get('TreatMissingData')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
