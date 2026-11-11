"""bucket-website-roundtrip."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-website-roundtrip"
GROUP = 'website_config'
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
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's implicit default: S3 rejects a LocationConstraint that
        # names it explicitly, so the parameter is only ever sent for a non-default region.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "project", "Value": "sim2real"}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises, because a target that accepts a call real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketWebsite persists the website config; DeleteBucketWebsite then GetBucketWebsite
    returns NoSuchWebsiteConfiguration."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    s3.put_bucket_website(
        Bucket=bucket,
        WebsiteConfiguration={
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "error.html"},
        },
    )

    cfg = s3.get_bucket_website(Bucket=bucket)
    assert cfg["IndexDocument"]["Suffix"] == "index.html", f"index doc not preserved: {cfg!r}"
    assert cfg["ErrorDocument"]["Key"] == "error.html", f"error doc not preserved: {cfg!r}"

    s3.delete_bucket_website(Bucket=bucket)
    code, message = _error(lambda: s3.get_bucket_website(Bucket=bucket))
    assert code == "NoSuchWebsiteConfiguration", f"expected NoSuchWebsiteConfiguration, got {code!r}"
    assert message == "The specified bucket does not have a website configuration", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
