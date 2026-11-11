"""put-metric-alarm-limit-exceeded-enforced."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-metric-alarm-limit-exceeded-enforced"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

# "Number of Metrics Insights alarms" is a fixed, non-adjustable quota of 200 per account per Region
# -- distinct from, and far smaller than, the general metric+ composite alarm quota of 5,000. A
# Metrics-Insights-query-based alarm is created via PutMetricAlarm's `Metrics` field with a `SELECT
# ...` expression instead of the plain MetricName/Namespace parameters, and shares the same
# LimitExceeded error once the quota is reached.
METRICS_INSIGHTS_ALARM_QUOTA = 200
_THROTTLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
}
_RETRY_DEADLINE_S = 240.0
LIMIT_MESSAGE = (
    f"The maximum limit of {METRICS_INSIGHTS_ALARM_QUOTA} metrics insights alarms would be exceeded."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """Creating Metrics Insights query alarms beyond the account's fixed 200/account
    quota is rejected with LimitExceeded."""
    cw = ctx.client("cloudwatch")
    current = _count_metrics_insights_alarms(cw)
    assert current <= METRICS_INSIGHTS_ALARM_QUOTA, (
        f"account already holds {current} Metrics Insights alarms, at/over the fixed "
        f"{METRICS_INSIGHTS_ALARM_QUOTA}/account quota; PutMetricAlarm should already "
        "be rejecting new ones with LimitExceeded"
    )
    headroom = METRICS_INSIGHTS_ALARM_QUOTA - current

    created: list[str] = []

    def _cleanup() -> None:
        for i in range(0, len(created), 100):
            batch = created[i : i + 100]
            try:
                cw.delete_alarms(AlarmNames=batch)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFound":
                    raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + _RETRY_DEADLINE_S
    attempts = headroom + 1
    for i in range(attempts):
        name = ctx.unique_name(f"sim2real-behav-mialarm-{i}-")
        error = _put_metrics_insights_alarm(cw, name, deadline)
        if error is None:
            created.append(name)
            continue
        assert error.get("Code") == "LimitExceeded", (
            f"expected LimitExceeded once the Metrics Insights alarm quota was reached, got {error!r}"
        )
        assert error.get("Message") == LIMIT_MESSAGE, error.get("Message")
        assert len(created) >= headroom, (
            f"hit LimitExceeded after only {len(created)} creates; expected to first use up "
            f"the {headroom} remaining headroom"
        )
        resp = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])
        assert resp.get("MetricAlarms", []) == [], (
            "a PutMetricAlarm call rejected with LimitExceeded must not create the alarm"
        )
        return
    raise AssertionError(
        f"created {len(created)} Metrics Insights alarms without ever hitting "
        f"LimitExceeded; the assumed quota of {METRICS_INSIGHTS_ALARM_QUOTA} may be stale"
    )


def _metrics_insights_query() -> dict:
    return {
        "Id": "q1",
        "Expression": 'SELECT AVG(CPUUtilization) FROM SCHEMA("AWS/EC2", InstanceId)',
        "Period": 300,
        "ReturnData": True,
    }


def _is_metrics_insights_alarm(alarm: dict) -> bool:
    for query in alarm.get("Metrics", []) or []:
        if query.get("Expression", "").strip().upper().startswith("SELECT"):
            return True
    return False


def _count_metrics_insights_alarms(cw: Any) -> int:
    total = 0
    paginator = cw.get_paginator("describe_alarms")
    for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
        total += sum(1 for alarm in page.get("MetricAlarms", []) if _is_metrics_insights_alarm(alarm))
    return total


def _put_metrics_insights_alarm(cw: Any, name: str, deadline: float) -> str | None:
    """Attempt one create; return None on success, or the botocore Error dict on failure.

    Retries a bounded number of times, only on throttling, without ever crossing
    `deadline` -- PutMetricAlarm's own request-rate quota (3/second by default) means
    a run of ~200 calls is expected to be throttled occasionally.
    """
    while True:
        try:
            cw.put_metric_alarm(
                AlarmName=name,
                AlarmDescription="behavioral check: Metrics Insights alarm quota probe",
                Metrics=[_metrics_insights_query()],
                EvaluationPeriods=1,
                Threshold=1_000_000.0,
                ComparisonOperator="GreaterThanThreshold",
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
            return None
        except ClientError as exc:
            error = exc.response["Error"]
            if error.get("Code") in _THROTTLE_CODES and time.monotonic() < deadline:
                time.sleep(1.0)
                continue
            return error


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
