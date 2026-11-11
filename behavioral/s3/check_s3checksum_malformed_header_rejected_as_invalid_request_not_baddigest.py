"""s3checksum-malformed-header-rejected-as-invalid-request-not-baddigest."""

from __future__ import annotations

import base64
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3checksum-malformed-header-rejected-as-invalid-request-not-baddigest"
GROUP = 'checksum-rejection'
SERVICES = ['s3']

_PAYLOAD = b"two-distinct-refusals-guard-one-header-" * 160


def _delete_bucket(client, bucket):
    """Abort open uploads, empty a bucket (objects + versions + markers), then delete it."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(
                    Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"]
                )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
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
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    return name


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _sha256_b64(data: bytes) -> str:
    """The base64 SHA-256 of ``data``, in the form S3 puts in ChecksumSHA256."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A wrong-sized ChecksumSHA256 header is InvalidRequest; a wrong-valued one is BadDigest,
    since S3 validates the header's shape before comparing. Neither stores anything, and the
    true digest is accepted.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    correct = _sha256_b64(_PAYLOAD)
    wrong_value = _sha256_b64(_PAYLOAD + b"x")
    # Valid base64, but three bytes where a SHA-256 is thirty-two.
    short = base64.b64encode(b"abc").decode()
    assert len(base64.b64decode(short)) == 3, "the malformed digest must decode to 3 bytes"
    assert len(base64.b64decode(correct)) == 32, "a SHA-256 digest is 32 bytes"

    # --- Refusal 1: the header is the wrong SHAPE. This must not be a digest comparison.
    exc_short = _client_error(
        lambda: s3.put_object(
            Bucket=bucket, Key="malformed.bin", Body=_PAYLOAD, ChecksumSHA256=short
        )
    )
    assert exc_short is not None, (
        f"PutObject accepted ChecksumSHA256={short!r}, which decodes to 3 bytes; a SHA-256 "
        "header of the wrong length must be refused before any comparison happens"
    )
    short_code = exc_short.response.get("Error", {}).get("Code")
    short_status = exc_short.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert short_code == "InvalidRequest", (
        f"expected InvalidRequest for a 3-byte SHA-256 header, got {short_code!r}"
    )
    assert short_status == 400, f"expected HTTP 400 for InvalidRequest, got {short_status!r}"
    short_message = exc_short.response.get("Error", {}).get("Message")
    assert short_message == "Value for x-amz-checksum-sha256 header is invalid.", (
        f"the malformed-header refusal's message is {short_message!r}"
    )

    # --- Refusal 2: the header is well-formed but does not describe the bytes.
    exc_value = _client_error(
        lambda: s3.put_object(
            Bucket=bucket, Key="mismatched.bin", Body=_PAYLOAD, ChecksumSHA256=wrong_value
        )
    )
    assert exc_value is not None, (
        f"PutObject accepted ChecksumSHA256={wrong_value!r} for a body whose true digest is "
        f"{correct!r}"
    )
    value_code = exc_value.response.get("Error", {}).get("Code")
    value_status = exc_value.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert value_code == "BadDigest", (
        f"expected BadDigest for a well-formed but mismatched SHA256, got {value_code!r}"
    )
    assert value_status == 400, f"expected HTTP 400 for BadDigest, got {value_status!r}"
    value_message = exc_value.response.get("Error", {}).get("Message")
    assert value_message == "The SHA256 you specified did not match the calculated checksum.", (
        f"the mismatched-digest refusal's message is {value_message!r}"
    )

    # --- The claim: the two classes are distinguished, not collapsed onto one code.
    assert short_code != value_code, (
        f"a malformed header and a mismatched value both returned {short_code!r}; S3 separates "
        "shape validation (InvalidRequest) from digest comparison (BadDigest), and collapsing "
        "them hides which half of the contract an implementation actually has"
    )

    # --- Effect absent: neither refused PUT stored anything.
    for key in ("malformed.bin", "mismatched.bin"):
        missing = _client_error(lambda k=key: s3.head_object(Bucket=bucket, Key=k))
        assert missing is not None, f"the refused PutObject stored {key!r} anyway"
        assert missing.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
            f"HeadObject for {key!r} returned "
            f"{missing.response['ResponseMetadata']['HTTPStatusCode']!r}, expected 404"
        )
    listed = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        listed += [o["Key"] for o in page.get("Contents", [])]
    assert listed == [], f"the bucket holds {listed!r} after two refused PUTs; it must be empty"

    # --- POSITIVE CONTROL: the same bytes with the true digest.
    stored = s3.put_object(
        Bucket=bucket, Key="accepted.bin", Body=_PAYLOAD, ChecksumSHA256=correct
    )
    assert stored["ChecksumSHA256"] == correct, (
        f"the accepted PutObject echoed {stored['ChecksumSHA256']!r}, the client computed "
        f"{correct!r} with hashlib over the same {len(_PAYLOAD)} bytes"
    )
    got = s3.get_object(Bucket=bucket, Key="accepted.bin", ChecksumMode="ENABLED")
    body = got["Body"].read()
    assert body == _PAYLOAD, f"the stored object is {len(body)} bytes, want {len(_PAYLOAD)}"
    assert _sha256_b64(body) == got["ChecksumSHA256"] == correct, (
        f"the bytes S3 returned hash to {_sha256_b64(body)!r}, S3 reported "
        f"{got['ChecksumSHA256']!r}, and the client computed {correct!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
