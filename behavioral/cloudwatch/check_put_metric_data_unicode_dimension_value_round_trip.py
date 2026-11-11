"""put-metric-data-unicode-dimension-value-round-trip."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-unicode-dimension-value-round-trip"
GROUP = "representation"
SERVICES = ["cloudwatch"]

# Empirically, real CloudWatch dimension values must be pure ASCII (API_Dimension.html:
# "must contain only ASCII characters"); non-ASCII (accented Latin, CJK, emoji) is
# rejected outright with InvalidParameterValue rather than being stored/mangled/
# transliterated. A fidelity bug here would show up as the emulator *accepting* and
# silently corrupting/truncating the value where real AWS rejects the call wholesale
# and persists nothing -- i.e. an overly-permissive divergence.
_UNICODE_DIM_VALUE = "café-🚀-日本語-Server_01"
_ASCII_DIM_VALUE = "cafe-rocket-nihongo-Server_01"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A non-ASCII dimension value is rejected wholesale and a pure-ASCII sibling round-trips
    unchanged; once the sibling is readable, the rejected metric is absent from the same reads."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-uni-")
    bad_metric = ctx.unique_name("UnicodeDimMetric-")
    good_metric = ctx.unique_name("AsciiDimMetric-")
    now = datetime.now(timezone.utc)

    try:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": bad_metric,
                    "Dimensions": [{"Name": "Host", "Value": _UNICODE_DIM_VALUE}],
                    "Timestamp": now,
                    "Value": 42.5,
                    "Unit": "None",
                }
            ],
        )
        raise AssertionError("non-ASCII dimension value was accepted instead of rejected")
    except ClientError as err:
        error = err.response["Error"]
        assert error["Code"] == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
        assert error["Message"] == (
            "The value for parameter MetricData.member.1.Dimensions.member.1.Value contains "
            "non-ASCII characters."
        ), error["Message"]

    # Positive control: the ASCII sibling on the same namespace is accepted and its
    # dimension value round-trips byte-identical via ListMetrics.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": good_metric,
                "Dimensions": [{"Name": "Host", "Value": _ASCII_DIM_VALUE}],
                "Timestamp": now,
                "Value": 42.5,
                "Unit": "None",
            }
        ],
    )
    metric = _poll_until(
        lambda: _find_metric(cw, namespace, good_metric),
        lambda m: m is not None,
        timeout_s=240.0,
        budget_s=_budget_s(ctx, 240.0),
        interval_s=10.0,
    )
    assert metric is not None, "ASCII-dim metric never appeared in ListMetrics"
    dims = {d["Name"]: d["Value"] for d in metric["Dimensions"]}
    assert dims["Host"] == _ASCII_DIM_VALUE, f"dimension value corrupted: {dims['Host']!r} != {_ASCII_DIM_VALUE!r}"
    # Effect absent, read only once the sibling is listed: ListMetrics registration is
    # asynchronous ("allow up to 15 minutes for the metric to appear").
    list_resp = cw.list_metrics(Namespace=namespace, MetricName=bad_metric)
    assert list_resp["Metrics"] == [], f"rejected unicode-dim metric was registered in ListMetrics anyway: {list_resp['Metrics']!r}"

    # Cross-check via GetMetricData: querying with the exact ASCII dimension value
    # must retrieve the datapoint we wrote (proves storage matched the query key exactly).
    result = _poll_until(
        lambda: cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": namespace,
                            "MetricName": good_metric,
                            "Dimensions": [{"Name": "Host", "Value": _ASCII_DIM_VALUE}],
                        },
                        "Period": 60,
                        "Stat": "Average",
                    },
                    "ReturnData": True,
                }
            ],
            StartTime=now.replace(microsecond=0) - timedelta(minutes=5),
            EndTime=now.replace(microsecond=0) + timedelta(minutes=1),
        ),
        lambda r: len(r["MetricDataResults"][0]["Values"]) > 0,
        timeout_s=180.0,
        budget_s=_budget_s(ctx, 180.0),
        interval_s=10.0,
    )
    values = result["MetricDataResults"][0]["Values"]
    assert values and abs(values[0] - 42.5) < 1e-6, f"unexpected values via ASCII-dim query: {values}"

    # Effect absent, read only once the sibling's datapoint in the same window is readable.
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=bad_metric,
        StartTime=now - timedelta(minutes=5),
        EndTime=now + timedelta(minutes=5),
        Period=60,
        Statistics=["Average"],
    )
    assert resp["Datapoints"] == [], f"rejected unicode-dim metric was persisted anyway: {resp['Datapoints']!r}"


def _find_metric(cw, namespace, metric_name):
    resp = cw.list_metrics(Namespace=namespace, MetricName=metric_name)
    metrics = resp.get("Metrics", [])
    return metrics[0] if metrics else None


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, budget_s=None):
    """Poll until predicate holds; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    import time

    start = time.monotonic()
    deadline = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            if budget_s is not None and budget_s < timeout_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{timeout_s}s wait ended (last={result!r}); not graded"
                )
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

