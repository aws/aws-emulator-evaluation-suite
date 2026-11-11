"""deep-cloudwatch-3-cwentity-omitted-strict-flag-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deep-cloudwatch-3-cwentity-omitted-strict-flag-rejected"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

_ENTITY_METRIC = "EntityFlagged"
_PLAIN_METRIC = "PlainUnflagged"
_OMITTED_VALUE = 31.0
_FLAGGED_VALUE = 47.0
_PLAIN_VALUE = 59.0
# A VALID entity: the only thing wrong with the refused request is the missing flag.
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
    """PutMetricData with EntityMetricData but no StrictEntityValidation is refused and ingests
    nothing; the same entity with the flag, and plain MetricData without it, both ingest.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealCwEntity")
    # CloudWatch has no DeleteMetric API; the unique namespace expires with its datapoints.
    ts = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    def _entity_data(value):
        return [
            {
                "Entity": {"KeyAttributes": dict(_KEY_ATTRIBUTES)},
                "MetricData": [{"MetricName": _ENTITY_METRIC, "Value": value, "Timestamp": ts}],
            }
        ]

    # The model types the flag as optional, but real AWS requires it whenever EntityMetricData is set.
    code, message = _error(
        lambda: cw.put_metric_data(Namespace=namespace, EntityMetricData=_entity_data(_OMITTED_VALUE))
    )
    assert code == "InvalidParameterCombination", (
        f"EntityMetricData with StrictEntityValidation omitted failed with {code!r} ({message!r}), "
        f"expected 'InvalidParameterCombination'"
    )
    assert message == "Field StrictEntityValidation is required when setting EntityMetricData", (
        f"the refusal does not name the missing flag: {message!r}"
    )

    flagged = cw.put_metric_data(
        Namespace=namespace,
        EntityMetricData=_entity_data(_FLAGGED_VALUE),
        StrictEntityValidation=False,
    )
    assert flagged["ResponseMetadata"]["HTTPStatusCode"] == 200, f"{flagged['ResponseMetadata']!r}"
    headers = {k.lower(): v for k, v in flagged["ResponseMetadata"]["HTTPHeaders"].items()}
    assert "x-amz-failure-message" not in headers, (
        f"a VALID entity was reported as dropped: x-amz-failure-message="
        f"{headers.get('x-amz-failure-message')!r}"
    )

    plain = cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": _PLAIN_METRIC, "Value": _PLAIN_VALUE, "Timestamp": ts}],
    )
    assert plain["ResponseMetadata"]["HTTPStatusCode"] == 200, f"{plain['ResponseMetadata']!r}"

    entity_points = _poll_datapoints(cw, namespace, _ENTITY_METRIC, ts, lambda d: len(d) >= 1)
    plain_points = _poll_datapoints(cw, namespace, _PLAIN_METRIC, ts, lambda d: len(d) >= 1)

    assert len(entity_points) == 1, f"{entity_points!r}"
    ep = entity_points[0]
    assert ep["SampleCount"] == 1.0 and ep["Sum"] == _FLAGGED_VALUE, (
        f"the entity metric holds {ep!r}; exactly one sample of {_FLAGGED_VALUE!r} was expected -- "
        f"a sum including {_OMITTED_VALUE!r} means the refused request ingested"
    )
    assert len(plain_points) == 1, f"{plain_points!r}"
    pp = plain_points[0]
    assert pp["SampleCount"] == 1.0 and pp["Sum"] == _PLAIN_VALUE, (
        f"plain MetricData with no flag was not ingested as published: {pp!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected SUCCESS is itself a failure."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"call was expected to be refused but succeeded: {resp!r}")


def _poll_datapoints(cw, namespace, metric, ts, predicate, *, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = []
    while True:
        last = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            StartTime=ts - timedelta(minutes=5),
            EndTime=ts + timedelta(minutes=5),
            Period=60,
            Statistics=["SampleCount", "Sum", "Minimum", "Maximum"],
        )["Datapoints"]
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
