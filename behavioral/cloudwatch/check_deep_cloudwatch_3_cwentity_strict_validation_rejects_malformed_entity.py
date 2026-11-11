"""deep-cloudwatch-3-cwentity-strict-validation-rejects-malformed-entity."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deep-cloudwatch-3-cwentity-strict-validation-rejects-malformed-entity"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

_METRIC = "EntityGated"
_STRICT_VALUE = 111.0
_LENIENT_VALUE = 222.0
# "NotARealType" is not one of the entity Types CloudWatch knows, so the KeyAttributes map is
# malformed in exactly one way: its Type value. Everything else about the request is valid.
_MALFORMED_KEY_ATTRIBUTES = {"Type": "NotARealType", "Name": "sim2real-entity"}


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
    """StrictEntityValidation=true refuses the whole PutMetricData on a malformed entity and ingests
    nothing; with false the datapoint is ingested and the dropped entity is reported in a header.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricData.html
    """
    cw = ctx.client("cloudwatch")
    # CloudWatch has no DeleteMetric API; the unique namespace expires with its datapoints.
    namespace = ctx.unique_name("Sim2RealCwEntity")
    ts = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    def _put(strict: bool, value: float):
        return cw.put_metric_data(
            Namespace=namespace,
            EntityMetricData=[
                {
                    "Entity": {"KeyAttributes": dict(_MALFORMED_KEY_ATTRIBUTES)},
                    "MetricData": [{"MetricName": _METRIC, "Value": value, "Timestamp": ts}],
                }
            ],
            StrictEntityValidation=strict,
        )

    # Negative arm: strict validation must refuse the whole request.
    code, message = _error(lambda: _put(True, _STRICT_VALUE))
    assert code == "InvalidParameterValue", (
        f"strict PutMetricData with entity Type 'NotARealType' failed with {code!r} ({message!r}), "
        f"expected 'InvalidParameterValue'"
    )
    assert message == "InvalidTypeValue: Unknown entity type", (
        f"the strict refusal names cause {message!r}; expected the documented 'InvalidTypeValue' "
        f"failure for an unknown entity Type"
    )

    # Positive control: the identical request with only the flag flipped is accepted. The API
    # reference names the header X-Amzn-Failure-Message; AWS sends x-amz-failure-message.
    resp = _put(False, _LENIENT_VALUE)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"lenient PutMetricData returned HTTP {status!r}, expected 200"
    headers = {k.lower(): v for k, v in resp["ResponseMetadata"]["HTTPHeaders"].items()}
    assert headers.get("x-amz-failure-message") == "InvalidTypeValue", (
        f"lenient PutMetricData dropped a malformed entity but its x-amz-failure-message header is "
        f"{headers.get('x-amz-failure-message')!r}, expected 'InvalidTypeValue'; failure-ish headers "
        f"were { {k: v for k, v in headers.items() if 'fail' in k}!r}"
    )

    # Both arms share one metric and timestamp, so once the lenient datapoint is readable the
    # absence of the strict value (111) is meaningful.
    points = _poll_datapoints(cw, namespace, _METRIC, ts, lambda dps: len(dps) >= 1)
    assert len(points) == 1, f"expected exactly one 60s datapoint, got {points!r}"
    point = points[0]
    assert point["SampleCount"] == 1.0, (
        f"the metric holds {point['SampleCount']!r} samples; the strict request must have ingested "
        f"nothing, so only the lenient sample may exist: {point!r}"
    )
    assert point["Sum"] == _LENIENT_VALUE, (
        f"the ingested sample sums to {point['Sum']!r}, expected the lenient value "
        f"{_LENIENT_VALUE!r} -- {_STRICT_VALUE!r} would mean the strict request ingested: {point!r}"
    )
    assert point["Minimum"] == point["Maximum"] == _LENIENT_VALUE, f"{point!r}"


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
