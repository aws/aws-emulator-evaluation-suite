"""lifecycle-transition-server-side."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "lifecycle-transition-server-side"
GROUP = 'lifecycle_rules'
SERVICES = ['s3']

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
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
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Transition lifecycle rule (prefix transition-, STANDARD_IA after 30 days) is accepted and read
    back exactly by GetBucketLifecycleConfiguration, and an object written under it starts in
    STANDARD."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "sim2real-transition-rule",
                    "Filter": {"Prefix": "transition-"},
                    "Status": "Enabled",
                    "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}],
                }
            ]
        },
    )

    cfg = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    (rule,) = [r for r in cfg["Rules"] if r["ID"] == "sim2real-transition-rule"]
    assert rule["Status"] == "Enabled", f"expected Status Enabled, got {rule['Status']!r}"
    assert rule["Filter"]["Prefix"] == "transition-", (
        f"expected Filter Prefix 'transition-', got {rule['Filter'].get('Prefix')!r}"
    )
    assert rule["Transitions"][0]["StorageClass"] == "STANDARD_IA", (
        f"expected transition StorageClass STANDARD_IA, got {rule['Transitions'][0]['StorageClass']!r}"
    )
    assert rule["Transitions"][0]["Days"] == 30, (
        f"expected transition Days 30, got {rule['Transitions'][0]['Days']!r}"
    )

    key = "transition-object.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"pre-transition-payload")

    head = s3.head_object(Bucket=bucket, Key=key)
    # S3 omits StorageClass entirely for the STANDARD default.
    assert head.get("StorageClass") in (None, "STANDARD"), (
        f"a freshly PUT object matched by a (not-yet-elapsed) transition rule must still "
        f"report STANDARD, got {head.get('StorageClass')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
