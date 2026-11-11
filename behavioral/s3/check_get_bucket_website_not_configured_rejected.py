"""get-bucket-website-not-configured-rejected."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "get-bucket-website-not-configured-rejected"
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
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "project", "Value": "sim2real"}]}
    )
    return name


def _err(fn, what):
    """Call fn(); return the botocore Error dict it raised. A success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"{what} succeeded; expected a refusal")


_NO_WEBSITE_MESSAGE = "The specified bucket does not have a website configuration"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBucketWebsite on a bucket with no website config fails with NoSuchWebsiteConfiguration;
    after PutBucketWebsite it reflects the config, and after DeleteBucketWebsite it fails again."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    err = _err(lambda: s3.get_bucket_website(Bucket=bucket), "GetBucketWebsite before any website config")
    assert err.get("Code") == "NoSuchWebsiteConfiguration", f"expected NoSuchWebsiteConfiguration, got {err}"
    assert err.get("Message") == _NO_WEBSITE_MESSAGE, err.get("Message")

    # Positive control: once a real config exists, the identical read succeeds and reflects it.
    s3.put_bucket_website(
        Bucket=bucket,
        WebsiteConfiguration={
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "error.html"},
        },
    )
    got = s3.get_bucket_website(Bucket=bucket)
    assert got["IndexDocument"] == {"Suffix": "index.html"}, f"index doc not reflected: {got!r}"
    assert got["ErrorDocument"] == {"Key": "error.html"}, f"error doc not reflected: {got!r}"

    # Break it again: deleting the config must restore the original rejection, not a stale success.
    s3.delete_bucket_website(Bucket=bucket)
    err_after = _err(lambda: s3.get_bucket_website(Bucket=bucket), "GetBucketWebsite after DeleteBucketWebsite")
    assert err_after.get("Code") == "NoSuchWebsiteConfiguration", (
        f"expected NoSuchWebsiteConfiguration after delete, got {err_after}"
    )
    assert err_after.get("Message") == _NO_WEBSITE_MESSAGE, err_after.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
