"""put-bucket-metrics-configuration-invalid-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-bucket-metrics-configuration-invalid-id-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A metrics configuration ID over the documented 64-character limit is rejected as invalid."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-metrics-")
    s3.create_bucket(Bucket=bucket, **_bucket_location_kwargs(s3))
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    # Per the PutBucketMetricsConfiguration docs: "The ID has a 64 character limit and can
    # only contain letters, numbers, periods, dashes, and underscores."
    too_long_id = "x" * 65
    code = _expect_error_code(
        lambda: s3.put_bucket_metrics_configuration(
            Bucket=bucket,
            Id=too_long_id,
            MetricsConfiguration={"Id": too_long_id},
        )
    )
    assert code == ("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema"), f"expected MalformedXML, got {code}"

    # effect absent: no configuration was ever created under that (invalid) id
    get_code = _expect_error_code(
        lambda: s3.get_bucket_metrics_configuration(Bucket=bucket, Id=too_long_id)
    )
    assert get_code == ("NoSuchConfiguration", "The specified configuration does not exist."), (
        f"expected NoSuchConfiguration, got {get_code}"
    )

    # positive control: a valid, within-limits id succeeds
    valid_id = "ValidMetricsId123"
    s3.put_bucket_metrics_configuration(
        Bucket=bucket, Id=valid_id, MetricsConfiguration={"Id": valid_id}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=valid_id))
    got = s3.get_bucket_metrics_configuration(Bucket=bucket, Id=valid_id)
    assert got["MetricsConfiguration"]["Id"] == valid_id, (
        f"expected {valid_id!r}, got {got['MetricsConfiguration'].get('Id')!r}"
    )


def _bucket_location_kwargs(s3):
    region = s3.meta.region_name
    if region and region != "us-east-1":
        return {"CreateBucketConfiguration": {"LocationConstraint": region}}
    return {}


def _expect_error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
