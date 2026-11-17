"""get-object-attributes-on-a-permanently-deleted-version-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-object-attributes-on-a-permanently-deleted-version-rejected"
GROUP = "object-version-rejected"
SERVICES = ["s3"]

_KEY = "ledger/entry.bin"
_V1_BODY = b"entry one"
_V2_BODY = b"entry two, revised"

_NO_SUCH_VERSION = ("NoSuchVersion", "The specified version does not exist.")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAttributes on a version id that was permanently deleted is refused NoSuchVersion,
    not NoSuchKey, while the key's current (newer) version still answers.
    """
    s3 = ctx.client("s3")
    bucket = _new_versioned_bucket(ctx, s3)

    v1 = s3.put_object(Bucket=bucket, Key=_KEY, Body=_V1_BODY)["VersionId"]
    put2 = s3.put_object(Bucket=bucket, Key=_KEY, Body=_V2_BODY)
    v2 = put2["VersionId"]

    # Naming a VersionId on DeleteObject erases exactly that version outright: no delete marker,
    # no new version — the version id is simply gone from here on.
    s3.delete_object(Bucket=bucket, Key=_KEY, VersionId=v1)

    expect_error(
        lambda: s3.get_object_attributes(
            Bucket=bucket, Key=_KEY, VersionId=v1, ObjectAttributes=["ETag", "ObjectSize"]
        ),
        *_NO_SUCH_VERSION,
    )

    # --- Positive control: the key's current (newer) version still answers, and its
    # GetObjectAttributes ETag is the PutObject ETag with the surrounding quotes stripped.
    current = s3.get_object_attributes(
        Bucket=bucket, Key=_KEY, VersionId=v2, ObjectAttributes=["ETag", "ObjectSize"]
    )
    assert current.get("ETag") == put2["ETag"].strip('"'), (
        f"GetObjectAttributes ETag must be the PutObject ETag {put2['ETag']!r} with the quotes "
        f"stripped; got {current.get('ETag')!r}"
    )
    assert current.get("ObjectSize") == len(_V2_BODY), (
        f"the surviving version's size must match its {len(_V2_BODY)}-byte body; got "
        f"{current.get('ObjectSize')!r}"
    )


def expect_error(fn, code: str, message: str) -> None:
    """Call fn(); assert its exact (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == code, f"expected code {code!r}, got {err.get('Code')!r}"
        assert err.get("Message") == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected ({code}, {message!r}), but the call succeeded: {result!r}")


def _new_versioned_bucket(ctx, s3) -> str:
    """A uniquely-named, versioned bucket; empty+delete teardown registered at once."""
    name = ctx.unique_name("sim2real-goadelv-")
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint
        # there, so it must be omitted rather than passed.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return name


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Delete every object version and delete marker, then the bucket. A failed delete raises;
    only the bucket already being gone is tolerated."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])
            ]
            if objs:
                out = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
                if out.get("Errors"):
                    raise AssertionError(f"cleanup could not delete {out['Errors'][:3]!r}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
