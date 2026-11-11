"""describe-alarm-contributors-reflects-composite-members."""
from __future__ import annotations

import datetime as dt
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-alarm-contributors-reflects-composite-members"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """DescribeAlarmContributors returns the individual time-series members composing a
    multi-time-series (GROUP BY Metrics Insights) alarm, and rejects a plain metric alarm
    that is not contributor-based."""
    cw = ctx.client("cloudwatch")
    describe_contributors = _require_op(cw, "DescribeAlarmContributors")

    # Negative sanity check: an ordinary single-series metric alarm has no contributors.
    plain_alarm = ctx.unique_name("sim2real-plain-alarm-")
    cw.put_metric_alarm(
        AlarmName=plain_alarm,
        Namespace="Sim2RealBehavioral/Contributors",
        MetricName="PlainMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[plain_alarm])))
    code, message = _client_error(lambda: describe_contributors(AlarmName=plain_alarm))
    assert code == "ValidationError", (
        f"expected ValidationError for a non-contributor alarm, got {code!r}"
    )
    expected_message = f"Alarm {plain_alarm} is not a multi time series alarm"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive: a multi-time-series alarm (Metrics Insights GROUP BY) exposes member contributors.
    namespace = ctx.unique_name("Sim2RealMTS")
    metric_name = "Latency"
    dim_key = "Contributor"
    contributor_values = {"east": 250.0, "west": 300.0}
    now = dt.datetime.utcnow()
    for value_key, value in contributor_values.items():
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Dimensions": [{"Name": dim_key, "Value": value_key}],
                    "Timestamp": now,
                    "Value": value,
                    "Unit": "Milliseconds",
                }
            ],
        )

    mts_alarm = ctx.unique_name("sim2real-mts-alarm-")
    # Real CloudWatch rejects a GROUP BY Metrics Insights alarm expression without an
    # ORDER BY clause (and an implicit/explicit LIMIT) to bound the number of contributing
    # time series: "Metrics expression that return multi time series are only allowed for
    # MetricsInsights expression with an ORDER BY clause".
    # Grouping by a dimension additionally requires the SCHEMA() form of the FROM clause
    # naming that dimension; a bare quoted namespace (`FROM "namespace"`) has no notion of
    # dimensions to group by and is rejected as invalid syntax as soon as GROUP BY is parsed.
    # The ORDER BY clause requires the ranking expression to be the same aggregate function
    # call used in the SELECT list, not a bare field reference: a bare `ORDER BY Latency DESC`
    # is rejected by real CloudWatch with "Invalid syntax. 'LATENCY' is not a function"
    # because the parser expects a function call in that position.
    # Additionally, for a GROUP BY query the ORDER BY function call must be written with
    # EMPTY parentheses (it implicitly refers back to the single aggregate in the SELECT
    # list) -- repeating the metric name inside the parentheses, e.g. `ORDER BY MAX(Latency)
    # DESC`, is rejected by real CloudWatch with "Invalid syntax near '(Latency) DESC
    # LIMIT 10'" because the parser only accepts `MAX()` (no argument) in that position.
    query = (
        f'SELECT MAX({metric_name}) FROM SCHEMA("{namespace}", {dim_key}) GROUP BY {dim_key} '
        f"ORDER BY MAX() DESC LIMIT 10"
    )
    cw.put_metric_alarm(
        AlarmName=mts_alarm,
        Metrics=[{"Id": "m1", "Expression": query, "Period": 60, "ReturnData": True}],
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=100.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[mts_alarm])))

    def _contributors():
        try:
            resp = describe_contributors(AlarmName=mts_alarm)
        except Exception:
            return []
        return resp.get("AlarmContributors", [])

    # CloudWatch evaluates Metrics Insights alarms on their own schedule; give it a generous
    # bounded window before treating non-convergence as a skip rather than a failure.
    contributors = _poll_until_value(_contributors, lambda c: bool(c), timeout_s=360, interval_s=15)
    if not contributors:
        raise AssertionError(
            "multi-time-series alarm never surfaced contributors within the poll budget "
            "(evaluation latency)"
        )

    seen_values = set()
    for contributor in contributors:
        seen_values.update(contributor.get("ContributorAttributes", {}).values())
    # Every published contributor value (250.0, 300.0) exceeds the alarm's threshold of 100.0, so
    # both groups are breaching and the server-computed contributor set must be exactly both -- not
    # merely a non-empty intersection, which a target returning a single contributor (or any one
    # unrelated value) could satisfy.
    assert seen_values == set(contributor_values.keys()), (
        f"expected exactly the contributor attribute values {sorted(contributor_values)} "
        f"(both exceed the threshold of 100.0), got {sorted(seen_values)} in {contributors!r}"
    )


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _swallow(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _bound_method(client, operation_name):
    mapping = getattr(client.meta, "method_to_api_mapping", {})
    for method_name, op in mapping.items():
        if op == operation_name:
            return getattr(client, method_name)
    return None


def _require_op(client, operation_name):
    fn = _bound_method(client, operation_name)
    if fn is None:
        raise AssertionError(f"botocore in this environment has no operation {operation_name}")
    return fn


def _poll_until_value(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except Exception:
            last = None
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last if predicate(last) else None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
