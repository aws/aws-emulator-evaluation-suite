"""obs-s3-1-forged-metric-data-into-aws-s3-namespace-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "obs-s3-1-forged-metric-data-into-aws-s3-namespace-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "s3"]

_FILTER_ID = "sim2realobsforged"
_FORGED_VALUE = 7.0
#: AWS names the reserved prefix as "AWS/" whatever casing the caller sent.
_NS_REFUSAL = "The value AWS/ for parameter Namespace is invalid."


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """PutMetricData into AWS/S3 4xxErrors for a real bucket's metrics FilterId fails with HTTP 400
    InvalidParameterValue and its exact message and the series stays absent, while the same datum in
    a custom namespace reads back with the exact Sum."""
    s3 = ctx.client("s3")
    cw = ctx.client("cloudwatch")

    bucket = ctx.unique_name("sim2real-obs-s3-forged-")
    create_kwargs: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # transport-only fork
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: ctx.client("s3").delete_bucket(Bucket=bucket))
    s3.put_bucket_metrics_configuration(
        Bucket=bucket, Id=_FILTER_ID,
        MetricsConfiguration={"Id": _FILTER_ID, "Filter": {"Prefix": "forged/"}},
    )
    ctx.on_cleanup(
        lambda: ctx.client("s3").delete_bucket_metrics_configuration(Bucket=bucket, Id=_FILTER_ID)
    )

    dims = [{"Name": "BucketName", "Value": bucket}, {"Name": "FilterId", "Value": _FILTER_ID}]
    stamp = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    datum = [{"MetricName": "4xxErrors", "Dimensions": dims, "Timestamp": stamp,
              "Value": _FORGED_VALUE, "Unit": "Count"}]

    # ---- the forgery: rejected, exactly, in both spellings ---------------------------------- #
    for namespace in ("AWS/S3", "aws/s3"):
        code, status, message = _error(
            lambda ns=namespace: cw.put_metric_data(Namespace=ns, MetricData=datum)
        )
        assert (code, status, message) == ("InvalidParameterValue", 400, _NS_REFUSAL), (
            f"PutMetricData into {namespace!r} returned ({code!r}, {status!r}, {message!r}); real "
            f"AWS rejects any namespace beginning AWS/ (case-insensitively) with "
            f"InvalidParameterValue 400 {_NS_REFUSAL!r}, although the model's pattern '^[^:]' "
            f"admits it"
        )

    # ---- positive control: the identical datum in a custom namespace is stored -------------- #
    custom_ns = f"Sim2real/ObsS3/{bucket}"
    cw.put_metric_data(Namespace=custom_ns, MetricData=datum)

    def _read(namespace: str) -> list[dict]:
        return cw.get_metric_statistics(
            Namespace=namespace, MetricName="4xxErrors", Dimensions=dims,
            StartTime=stamp - timedelta(minutes=5), EndTime=stamp + timedelta(minutes=5),
            Period=60, Statistics=["Sum"],
        )["Datapoints"]

    deadline = time.monotonic() + 300
    control = _read(custom_ns)
    while not control:
        assert time.monotonic() < deadline, (
            f"the control datum in {custom_ns!r} was never readable within 300s; without it the "
            f"absence below proves nothing"
        )
        time.sleep(5)
        control = _read(custom_ns)
    assert [(float(d["Sum"]), d["Unit"]) for d in control] == [(_FORGED_VALUE, "Count")], (
        f"control read back {control!r}, expected one datapoint Sum {_FORGED_VALUE} Count"
    )

    # ---- effect absent: nothing landed in the real AWS/S3 series ---------------------------- #
    forged = _read("AWS/S3")
    assert forged == [], (
        f"AWS/S3 4xxErrors for [BucketName={bucket}, FilterId={_FILTER_ID}] holds {forged!r}; "
        f"this bucket never served a request, so any datapoint is the rejected forgery leaking in"
    )
    listed = cw.list_metrics(
        Namespace="AWS/S3", Dimensions=[{"Name": "BucketName", "Value": bucket}]
    )["Metrics"]
    assert listed == [], f"ListMetrics(AWS/S3) for the unused bucket {bucket!r} returned {listed!r}"


def _error(fn) -> tuple[str, int, str]:
    """(code, http status, message) of the error *fn* raised. Raises if it succeeded."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return (
            exc.response["Error"]["Code"],
            exc.response["ResponseMetadata"]["HTTPStatusCode"],
            exc.response["Error"].get("Message"),
        )
    raise AssertionError("call succeeded but an error was expected")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
