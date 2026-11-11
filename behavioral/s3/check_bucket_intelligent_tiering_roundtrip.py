"""bucket-intelligent-tiering-roundtrip."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-intelligent-tiering-roundtrip"
GROUP = 'intelligent_tiering'
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
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
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
    """Intelligent-Tiering configurations round-trip their tiering rules and are removable."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    tid = "archive-after-90d"

    s3.put_bucket_intelligent_tiering_configuration(
        Bucket=bucket, Id=tid,
        IntelligentTieringConfiguration={
            "Id": tid,
            "Status": "Enabled",
            "Tierings": [{"Days": 90, "AccessTier": "ARCHIVE_ACCESS"}],
        },
    )

    got = s3.get_bucket_intelligent_tiering_configuration(Bucket=bucket, Id=tid)[
        "IntelligentTieringConfiguration"
    ]
    assert got["Status"] == "Enabled", f"status not preserved: {got!r}"
    assert got["Tierings"] == [{"Days": 90, "AccessTier": "ARCHIVE_ACCESS"}], f"tierings not preserved: {got['Tierings']}"

    listed = s3.list_bucket_intelligent_tiering_configurations(Bucket=bucket).get(
        "IntelligentTieringConfigurationList", []
    )
    assert [c["Id"] for c in listed] == [tid], f"expected exactly [{tid!r}] listed, got {listed}"

    s3.delete_bucket_intelligent_tiering_configuration(Bucket=bucket, Id=tid)
    code, message = _client_error(
        lambda: s3.get_bucket_intelligent_tiering_configuration(Bucket=bucket, Id=tid)
    )
    assert code == "NoSuchConfiguration", f"expected NoSuchConfiguration, got {code!r}"
    expected = "The specified configuration does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_after = s3.list_bucket_intelligent_tiering_configurations(Bucket=bucket).get(
        "IntelligentTieringConfigurationList", []
    )
    assert listed_after == [], f"expected no configurations listed after delete, got {listed_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
