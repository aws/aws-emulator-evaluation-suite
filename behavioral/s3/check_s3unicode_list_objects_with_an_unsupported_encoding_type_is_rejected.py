"""s3unicode-list-objects-with-an-unsupported-encoding-type-is-rejected."""

from __future__ import annotations

import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3unicode-list-objects-with-an-unsupported-encoding-type-is-rejected"
GROUP = 'errors'
SERVICES = ['s3']


# ===== helpers (self-contained) =====
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
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _list_keys(s3, bucket, prefix, **kwargs):
    """Every key under ``prefix``, across all pages."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix, **kwargs):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _client_error(fn):
    """Call fn(); return the ClientError it raised. An unexpected SUCCESS raises, so a target
    accepting a call real AWS refuses is never mistaken for a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")
# ===== end helpers =====


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjectsV2 accepts only EncodingType=url: utf8 is refused with exactly InvalidArgument and no
    unencoded listing comes back, while url succeeds on a key holding a newline and an astral
    character, the case EncodingType exists for.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    emoji = "\U0001f600"
    prefix = "encneg/"
    key = f"{prefix}a\nb-{emoji}.txt"
    body = b"encoding-type-payload"
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    # --- Positive control: the one supported value encodes the newline and the astral character,
    #     and unquote_plus recovers the stored key exactly.
    encoded = _list_keys(s3, bucket, prefix, EncodingType="url")
    assert encoded == [f"{prefix}a%0Ab-%F0%9F%98%80.txt"], (
        f"EncodingType=url did not encode the key as expected: got {encoded!r}"
    )
    assert urllib.parse.unquote_plus(encoded[0]) == key, (
        f"the url-encoded key does not decode back to the stored key: decoded "
        f"{urllib.parse.unquote_plus(encoded[0])!r}, stored {key!r}"
    )

    # --- Break exactly one thing: ask for an encoding S3 does not support.
    # An unexpected success raises inside the helper: real S3 supports only 'url', and silently
    # ignoring an unknown value hands the caller raw keys it will then decode and corrupt.
    exc = _client_error(lambda: s3.list_objects_v2(Bucket=bucket, Prefix=prefix, EncodingType="utf8"))
    code = exc.response.get("Error", {}).get("Code")
    assert code == "InvalidArgument", (
        f"expected InvalidArgument for EncodingType='utf8', got {code!r}"
    )
    message = exc.response.get("Error", {}).get("Message")
    assert message == "Invalid Encoding Method specified in Request", message
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"expected HTTP 400 for InvalidArgument, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- Effect absent: the refusal returned no listing at all, rather than an unencoded one.
    assert "Contents" not in exc.response, (
        f"the refused ListObjectsV2 still carried a listing in its error response: "
        f"{exc.response.get('Contents')!r}"
    )

    # --- The bucket is unchanged, and both the unencoded and the supported encoded listing still
    #     report the key byte-exactly.
    raw = _list_keys(s3, bucket, prefix)
    assert raw == [key], (
        f"the unencoded listing is not byte-exact after the refusal: expected [{key!r}], got "
        f"{raw!r}"
    )
    again = _list_keys(s3, bucket, prefix, EncodingType="url")
    assert again == encoded, (
        f"EncodingType=url stopped working after the refused call: expected {encoded!r}, got "
        f"{again!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == body, (
        "the object's content was disturbed by the refused listing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
