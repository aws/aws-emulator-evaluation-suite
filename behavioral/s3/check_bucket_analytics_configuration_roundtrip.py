"""bucket-analytics-configuration-roundtrip."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-analytics-configuration-roundtrip"
GROUP = 'analytics_config'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    # us-east-1 is CreateBucket's implicit default and rejects an explicit LocationConstraint for it.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]})
    return name


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Analytics configurations are addressable by Id, enumerable, and removable (then
    NoSuchConfiguration)."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    aid = "whole-bucket-analytics"

    s3.put_bucket_analytics_configuration(
        Bucket=bucket, Id=aid,
        AnalyticsConfiguration={"Id": aid, "StorageClassAnalysis": {}},
    )

    got = s3.get_bucket_analytics_configuration(Bucket=bucket, Id=aid)["AnalyticsConfiguration"]
    assert got["Id"] == aid, f"analytics config id mismatch: {got!r}"

    listed = s3.list_bucket_analytics_configurations(Bucket=bucket).get("AnalyticsConfigurationList", [])
    assert [c["Id"] for c in listed] == [aid], f"expected exactly [{aid!r}] listed, got {listed}"

    s3.delete_bucket_analytics_configuration(Bucket=bucket, Id=aid)
    code, message = _client_error(lambda: s3.get_bucket_analytics_configuration(Bucket=bucket, Id=aid))
    assert code == "NoSuchConfiguration", f"expected NoSuchConfiguration, got {code!r}"
    expected = "The specified configuration does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_after = s3.list_bucket_analytics_configurations(Bucket=bucket).get("AnalyticsConfigurationList", [])
    assert listed_after == [], f"expected no analytics configs listed after delete, got {listed_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
