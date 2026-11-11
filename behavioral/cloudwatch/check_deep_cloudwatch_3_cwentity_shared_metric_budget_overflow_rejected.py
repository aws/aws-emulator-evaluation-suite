"""deep-cloudwatch-3-cwentity-shared-metric-budget-overflow-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deep-cloudwatch-3-cwentity-shared-metric-budget-overflow-rejected"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

# 1000 is a fixed API constant of PutMetricData (not a Service Quotas value), shared across
# MetricData + EntityMetricData. Neither half below exceeds it on its own.
_BUDGET = 1000
_PLAIN_N = 600
_ENTITY_N_OVER = _BUDGET - _PLAIN_N + 1   # 401: total 1001
_ENTITY_N_FIT = _BUDGET - _PLAIN_N        # 400: total 1000
_STRICT_OVER_VALUE = 1.0
_LENIENT_OVER_VALUE = 2.0
_FIT_VALUE = 3.0
_KEY_ATTRIBUTES = {"Type": "Service", "Name": "sim2real-entity", "Environment": "sim2real"}


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """600 plain + 401 entity metrics exceed PutMetricData's shared 1000-metric budget and are
    refused, strict or lenient, ingesting nothing; 600 + 400 ingests in full.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealCwBudget")
    # CloudWatch has no DeleteMetric API; the unique namespace expires with its datapoints.
    ts = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    def _data(prefix, n, value):
        return [{"MetricName": f"{prefix}{i}", "Value": value, "Timestamp": ts} for i in range(n)]

    def _put(entity_n, value, strict):
        return cw.put_metric_data(
            Namespace=namespace,
            MetricData=_data("plain", _PLAIN_N, value),
            EntityMetricData=[
                {
                    "Entity": {"KeyAttributes": dict(_KEY_ATTRIBUTES)},
                    "MetricData": _data("entity", entity_n, value),
                }
            ],
            StrictEntityValidation=strict,
        )

    for strict, value in ((True, _STRICT_OVER_VALUE), (False, _LENIENT_OVER_VALUE)):
        # The lenient flag does not relax the budget: it is a metric-data error, not an entity one.
        code, message = _error(lambda v=value, s=strict: _put(_ENTITY_N_OVER, v, s))
        assert code == "InvalidParameterValue", (
            f"{_PLAIN_N} plain + {_ENTITY_N_OVER} entity metrics (StrictEntityValidation={strict}) "
            f"failed with {code!r} ({message!r}), expected 'InvalidParameterValue' -- the budget "
            f"is shared, so this request is over it although neither list is"
        )
        assert message == "The collection MetricData must not have a size greater than 1000.", (
            f"unexpected InvalidParameterValue message {message!r}"
        )

    fit = _put(_ENTITY_N_FIT, _FIT_VALUE, True)
    assert fit["ResponseMetadata"]["HTTPStatusCode"] == 200, f"{fit['ResponseMetadata']!r}"

    for metric in ("plain0", f"plain{_PLAIN_N - 1}", "entity0", f"entity{_ENTITY_N_FIT - 1}"):
        points = _poll_datapoints(cw, namespace, metric, ts, lambda d: len(d) >= 1)
        assert len(points) == 1, f"{metric}: {points!r}"
        p = points[0]
        assert p["SampleCount"] == 1.0 and p["Sum"] == _FIT_VALUE, (
            f"{metric} holds {p!r}; exactly one sample of {_FIT_VALUE!r} was expected -- a sum "
            f"including {_STRICT_OVER_VALUE!r} or {_LENIENT_OVER_VALUE!r} means a refused request "
            f"was partially ingested"
        )

    # The 401st entity metric was only ever sent in the two refused requests.
    orphan = f"entity{_ENTITY_N_OVER - 1}"
    orphan_points = _datapoints(cw, namespace, orphan, ts)
    assert orphan_points == [], (
        f"{orphan} appeared only in refused requests yet holds datapoints {orphan_points!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected SUCCESS is itself a failure."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"call was expected to be refused but succeeded: {resp['ResponseMetadata']!r}")


def _datapoints(cw, namespace, metric, ts):
    return cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        StartTime=ts - timedelta(minutes=5),
        EndTime=ts + timedelta(minutes=5),
        Period=60,
        Statistics=["SampleCount", "Sum"],
    )["Datapoints"]


def _poll_datapoints(cw, namespace, metric, ts, predicate, *, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = []
    while True:
        last = _datapoints(cw, namespace, metric, ts)
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"metric {namespace}/{metric} never reached the expected state within "
                f"{timeout_s}s; last datapoints {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
