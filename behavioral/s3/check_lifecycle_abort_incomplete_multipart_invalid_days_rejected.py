"""lifecycle-abort-incomplete-multipart-invalid-days-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "lifecycle-abort-incomplete-multipart-invalid-days-rejected"
GROUP = 'lifecycle_rules'
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
        # us-east-1 rejects CreateBucketConfiguration entirely; every other region requires it.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A lifecycle rule with AbortIncompleteMultipartUpload DaysAfterInitiation=0 is rejected with
    InvalidArgument and the existing valid rule (DaysAfterInitiation=1) stays unchanged."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    valid_rule_id = "sim2real-valid-abort-mpu-rule"
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": valid_rule_id,
                    "Filter": {"Prefix": "mpu-valid-"},
                    "Status": "Enabled",
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
                }
            ]
        },
    )
    positive_cfg = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    (positive_rule,) = [r for r in positive_cfg["Rules"] if r["ID"] == valid_rule_id]
    assert positive_rule["AbortIncompleteMultipartUpload"]["DaysAfterInitiation"] == 1, (
        f"positive control: expected the valid DaysAfterInitiation=1 rule reflected back, got {positive_rule}"
    )

    err = _client_error(
        lambda: s3.put_bucket_lifecycle_configuration(
            Bucket=bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "sim2real-invalid-abort-mpu-rule",
                        "Filter": {"Prefix": "mpu-invalid-"},
                        "Status": "Enabled",
                        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 0},
                    }
                ]
            },
        )
    )
    assert err.get("Code") == "InvalidArgument", f"expected InvalidArgument for DaysAfterInitiation=0, got {err!r}"
    assert err.get("Message") == "'DaysAfterInitiation' for AbortIncompleteMultipartUpload action must be a positive integer", err

    cfg = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    rule_ids = {r["ID"] for r in cfg["Rules"]}
    assert rule_ids == {valid_rule_id}, (
        f"expected the rejected rule to never have been committed and the prior valid rule untouched, "
        f"got rule ids {rule_ids}"
    )
    (surviving_rule,) = [r for r in cfg["Rules"] if r["ID"] == valid_rule_id]
    assert surviving_rule["AbortIncompleteMultipartUpload"]["DaysAfterInitiation"] == 1, (
        f"expected the pre-existing valid rule left unmodified by the rejected put, got {surviving_rule}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
