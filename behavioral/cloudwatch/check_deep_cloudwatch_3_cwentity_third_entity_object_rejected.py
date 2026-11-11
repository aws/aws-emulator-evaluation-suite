"""deep-cloudwatch-3-cwentity-third-entity-object-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deep-cloudwatch-3-cwentity-third-entity-object-rejected"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

_STRICT_THREE_VALUE = 5.0
_STRICT_TWO_VALUE = 7.0
_LENIENT_THREE_VALUE = 9.0


def _entity(i):
    return {"Type": "Service", "Name": f"sim2real-entity-{i}", "Environment": "sim2real"}


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
    """Three EntityMetricData objects are refused under strict validation and ingest nothing new;
    two are accepted; lenient three returns EntitySizeTooLarge in a header yet ingests all metrics.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealCwEntityN")
    # CloudWatch has no DeleteMetric API; the unique namespace expires with its datapoints.
    ts = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    def _put(prefix, n, value, strict):
        return cw.put_metric_data(
            Namespace=namespace,
            EntityMetricData=[
                {
                    "Entity": {"KeyAttributes": _entity(i)},
                    "MetricData": [{"MetricName": f"{prefix}{i}", "Value": value, "Timestamp": ts}],
                }
                for i in range(n)
            ],
            StrictEntityValidation=strict,
        )

    # The model puts no length bound on EntityMetricDataList; the service caps it at two.
    # Its message says "shorter than 2" although two is accepted.
    code, message = _error(lambda: _put("t", 3, _STRICT_THREE_VALUE, True))
    assert code == "InvalidParameterValue", (
        f"three EntityMetricData objects under strict validation failed with {code!r} "
        f"({message!r}), expected 'InvalidParameterValue'"
    )
    assert message == "EntitySizeTooLarge: The total number of EntityMetricData elements must be shorter than 2", (
        f"the refusal names cause {message!r}; expected the documented 'EntitySizeTooLarge'"
    )

    two = _put("t", 2, _STRICT_TWO_VALUE, True)
    assert two["ResponseMetadata"]["HTTPStatusCode"] == 200, f"{two['ResponseMetadata']!r}"
    two_headers = {k.lower(): v for k, v in two["ResponseMetadata"]["HTTPHeaders"].items()}
    assert "x-amz-failure-message" not in two_headers, (
        f"two valid entities were reported as failing: {two_headers.get('x-amz-failure-message')!r}"
    )

    # The API reference documents X-Amzn-Failure-Message; the service sends x-amz-failure-message.
    lenient = _put("u", 3, _LENIENT_THREE_VALUE, False)
    assert lenient["ResponseMetadata"]["HTTPStatusCode"] == 200, f"{lenient['ResponseMetadata']!r}"
    lenient_headers = {k.lower(): v for k, v in lenient["ResponseMetadata"]["HTTPHeaders"].items()}
    assert lenient_headers.get("x-amz-failure-message") == "EntitySizeTooLarge", (
        f"lenient PutMetricData with three entity objects carries x-amz-failure-message="
        f"{lenient_headers.get('x-amz-failure-message')!r}, expected 'EntitySizeTooLarge'"
    )

    for metric, value in (("t0", _STRICT_TWO_VALUE), ("t1", _STRICT_TWO_VALUE),
                          ("u0", _LENIENT_THREE_VALUE), ("u1", _LENIENT_THREE_VALUE),
                          ("u2", _LENIENT_THREE_VALUE)):
        points = _poll_datapoints(cw, namespace, metric, ts, lambda d: len(d) >= 1)
        assert len(points) == 1, f"{metric}: {points!r}"
        p = points[0]
        assert p["SampleCount"] == 1.0 and p["Sum"] == value, (
            f"{metric} holds {p!r}; exactly one sample of {value!r} was expected (a sum including "
            f"{_STRICT_THREE_VALUE!r} means the refused three-object request was ingested)"
        )

    orphan = _datapoints(cw, namespace, "t2", ts)
    assert orphan == [], (
        f"t2 was sent only in the refused three-object request yet holds datapoints {orphan!r}"
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
