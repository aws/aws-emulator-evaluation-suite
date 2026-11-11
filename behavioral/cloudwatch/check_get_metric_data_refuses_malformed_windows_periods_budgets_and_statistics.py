"""get-metric-data-refuses-malformed-windows-periods-budgets-and-statistics."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-data-refuses-malformed-windows-periods-budgets-and-statistics"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

_M = "The parameter MetricDataQueries.member.1."
_WINDOW_EQUAL = ("ValidationError", "The parameter StartTime must not equal parameter EndTime.\n")
_WINDOW_INVERTED = ("ValidationError", "The parameter EndTime must be greater than StartTime.\n")
_SUB_MINUTE_PERIOD = ("ValidationError", _M + "MetricStat.Period must be a value in the set [ 1, 5, 10, 20, 30 ].\n")
_SUPER_MINUTE_PERIOD = ("ValidationError", _M + "MetricStat.Period must be a multiple of 60.\n")
_MAX_DATAPOINTS_ZERO = ("ValidationError", "The parameter MaxDatapoints must not equal 0.\n")
_MAX_DATAPOINTS_NEGATIVE = ("ValidationError", "The parameter MaxDatapoints must be greater than 0.\n")
_BAD_STAT = ("ValidationError", "The value for parameter MetricDataQueries.member.1.MetricStat.Stat is not a valid statistic.\n")
_BAD_ID = ("ValidationError",
           "The value for parameter MetricDataQueries.member.1.Id is not matching the expected pattern ^[a-z][a-zA-Z0-9_]*$.\n")
_BOTH_SHAPES = ("ValidationError", "The parameters MetricDataQueries.member.1.Expression and MetricDataQueries.member.1.MetricStat "
                "are mutually exclusive and you have specified both.\n")
_NO_SHAPE = ("ValidationError", _M + "MetricStat is required.\n")
_UNKNOWN_FUNCTION = ("ValidationError", "Error in expression 'e1': Function 'NOPE' not found")
_TOO_MANY_QUERIES = ("ValidationError", "The collection MetricDataQueries must not have a size greater than 500.\n")


def expect_error(fn, code, message, label="call"):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message", ""))
        assert got == (code, message), f"{label}: expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"{label}: expected {(code, message)!r}, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData refuses a malformed window, Period, MaxDatapoints, query count, statistic, query Id,
    query shape or math function with ValidationError and its exact message, while the neighbouring
    valid value on the same request shape is accepted."""
    cw = ctx.client("cloudwatch")
    # The namespace holds no data: every accepted read returns its queries with no values.
    namespace = ctx.unique_name("sim2real-cw-gmd-refuse-")
    start = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=10)
    end = start + timedelta(seconds=60)

    def stat(period=60, statistic="Sum"):
        return {"Metric": {"Namespace": namespace, "MetricName": "Shape"}, "Period": period, "Stat": statistic}

    def q(qid="m1", **fields):
        return {"Id": qid, "MetricStat": stat(), **fields}

    def call(queries=None, **overrides):
        kwargs = {"MetricDataQueries": queries or [q()], "StartTime": start, "EndTime": end, **overrides}
        return cw.get_metric_data(**kwargs)

    cases = [
        ("window equal", dict(EndTime=start), _WINDOW_EQUAL, [{}]),
        ("window inverted", dict(StartTime=end + timedelta(seconds=1)), _WINDOW_INVERTED, [{}]),
        ("sub-minute Period", dict(queries=[q(MetricStat=stat(period=7))]), _SUB_MINUTE_PERIOD,
         [dict(queries=[q(MetricStat=stat(period=5))]), dict(queries=[q(MetricStat=stat(period=30))])]),
        ("super-minute Period", dict(queries=[q(MetricStat=stat(period=90))]), _SUPER_MINUTE_PERIOD,
         [dict(queries=[q(MetricStat=stat(period=120))])]),
        ("MaxDatapoints 0", dict(MaxDatapoints=0), _MAX_DATAPOINTS_ZERO, [dict(MaxDatapoints=1)]),
        ("MaxDatapoints -1", dict(MaxDatapoints=-1), _MAX_DATAPOINTS_NEGATIVE, [dict(MaxDatapoints=1)]),
        ("lower-case statistic", dict(queries=[q(MetricStat=stat(statistic="sum"))]), _BAD_STAT, [{}]),
        ("percentile above 100", dict(queries=[q(MetricStat=stat(statistic="p101"))]), _BAD_STAT,
         [dict(queries=[q(MetricStat=stat(statistic="p100"))])]),
        ("upper-case Id", dict(queries=[q("M1")]), _BAD_ID, [dict(queries=[q("mA1_x")])]),
        ("Id with a symbol", dict(queries=[q("m-1")]), _BAD_ID, [dict(queries=[q("m1")])]),
        ("MetricStat and Expression", dict(queries=[q(Expression="TIME_SERIES(1)")]), _BOTH_SHAPES,
         [{}, dict(queries=[{"Id": "m1", "Expression": "TIME_SERIES(1)"}])]),
        ("neither MetricStat nor Expression", dict(queries=[{"Id": "m1"}]), _NO_SHAPE, [{}]),
        ("unknown math function", dict(queries=[q(ReturnData=False), {"Id": "e1", "Expression": "NOPE(m1)"}]),
         _UNKNOWN_FUNCTION, [dict(queries=[q(ReturnData=False), {"Id": "e1", "Expression": "ABS(m1)"}])]),
        ("501 queries", dict(queries=[q(f"m{i}") for i in range(501)]), _TOO_MANY_QUERIES, []),
    ]
    for label, refused, expected, accepted in cases:
        expect_error(lambda refused=refused: call(**refused), *expected, label=label)
        for overrides in accepted:
            queries = overrides.get("queries") or [q()]
            want = [x["Id"] for x in queries if x.get("ReturnData", True)]
            got = [r["Id"] for r in call(**overrides)["MetricDataResults"]]
            assert got == want, (
                f"{label}: expected the neighbouring valid value {overrides!r} to return the queries {want!r}, got {got!r}"
            )

    full = call(queries=[q(f"m{i}") for i in range(500)])
    got = sorted(r["Id"] for r in full["MetricDataResults"])
    assert got == sorted(f"m{i}" for i in range(500)), f"expected 500 queries to return one result each, got {got!r}"

    silent = call(queries=[q(ReturnData=False), q("m2", ReturnData=False)])
    assert silent["MetricDataResults"] == [], (
        f"expected all ReturnData=false queries to return an empty result list, got {silent['MetricDataResults']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
