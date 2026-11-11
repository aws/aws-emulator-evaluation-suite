"""deep-s3-immutability-copy-unknown-tagging-directive-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-immutability-copy-unknown-tagging-directive-rejected"
GROUP = 'copy-directives-rejection'
SERVICES = ['s3']

_BODY = b"source-for-a-copy-with-a-bogus-directive"


def _delete_bucket(client, bucket):
    """Delete every version and marker, then the bucket."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-imm-")
    params = {"Bucket": name}
    # us-east-1 is the one region that rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn, what):
    """Call fn(); return the ClientError (code, http status, message); a success fails."""
    try:
        resp = fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                exc.response.get("Error", {}).get("Message"))
    raise AssertionError(
        f"{what} unexpectedly SUCCEEDED (HTTP "
        f"{resp.get('ResponseMetadata', {}).get('HTTPStatusCode')!r}) where real AWS refuses it"
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject with a TaggingDirective outside {COPY, REPLACE} is rejected with InvalidArgument
    and writes no destination; the identical copy with REPLACE succeeds and replaces the tags."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="src.bin", Body=_BODY, Tagging="class=gold")
    source = {"Bucket": bucket, "Key": "src.bin"}

    # botocore does not enforce enums client side, so the bogus value reaches the service verbatim.
    code, status, message = _error(
        lambda: s3.copy_object(
            Bucket=bucket, Key="dest.bin", CopySource=source,
            TaggingDirective="MERGE", Tagging="class=silver",
        ),
        "a CopyObject with TaggingDirective=MERGE",
    )
    assert (code, status, message) == ("InvalidArgument", 400, "Unknown tagging directive."), (
        f"expected InvalidArgument/400 with AWS's exact message for an unknown TaggingDirective, "
        f"got {code!r}/{status!r}/{message!r}"
    )

    # Effect absent: nothing was written at the destination.
    absent, absent_status, _ = _error(
        lambda: s3.head_object(Bucket=bucket, Key="dest.bin"),
        "HeadObject of the destination the refused copy must not have written",
    )
    assert absent_status == 404, (
        f"after the refused copy, HeadObject on the destination returned {absent!r}/"
        f"{absent_status!r}; want 404 — the refused copy wrote an object"
    )

    # Positive control: the identical copy with a valid directive succeeds and replaces the tags.
    s3.copy_object(
        Bucket=bucket, Key="dest.bin", CopySource=source,
        TaggingDirective="REPLACE", Tagging="class=silver",
    )
    body = s3.get_object(Bucket=bucket, Key="dest.bin")["Body"].read()
    assert body == _BODY, f"the valid copy holds {body!r}, want {_BODY!r}"
    got = s3.get_object_tagging(Bucket=bucket, Key="dest.bin")["TagSet"]
    assert got == [{"Key": "class", "Value": "silver"}], (
        f"the valid REPLACE copy has tags {got!r}; want [class=silver]"
    )
    src_tags = s3.get_object_tagging(Bucket=bucket, Key="src.bin")["TagSet"]
    assert src_tags == [{"Key": "class", "Value": "gold"}], f"the source's tags changed: {src_tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
