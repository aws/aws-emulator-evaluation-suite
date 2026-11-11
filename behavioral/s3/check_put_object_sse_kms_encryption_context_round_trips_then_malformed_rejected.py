"""put-object-sse-kms-encryption-context-round-trips-then-malformed-rejected."""

from __future__ import annotations

import base64
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-sse-kms-encryption-context-round-trips-then-malformed-rejected"
GROUP = "encryption-context"
SERVICES = ["s3"]

_CONTEXT_HEADER = "x-amz-server-side-encryption-context"

#: The exact message real AWS returns for a malformed x-amz-server-side-encryption-context header.
_MALFORMED_MSG = (
    "The header 'x-amz-server-side-encryption-context' shall be Base64-encoded UTF-8 "
    "string holding JSON which represents a string-string map"
)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutObject's SSE-KMS encryption context comes back, augmented with the object's own ARN,
    on the PutObject response and on HeadObject; GetObject reports the KMS key.
    A context header that is not Base64 JSON is refused and creates no object.
    """
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    bucket = ctx.unique_name("sim2real-behav-ssectx-")
    _create_bucket(ctx, s3, bucket)

    key_id = kms.create_key(
        Description="sim2real-behav-ssectx",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]

    good_key = "context-echo.txt"
    sent_context = {"team": "sim2real"}
    sent_b64 = base64.b64encode(json.dumps(sent_context).encode()).decode()

    put = s3.put_object(
        Bucket=bucket, Key=good_key, Body=b"payload",
        ServerSideEncryption="aws:kms", SSEKMSKeyId=key_id,
        SSEKMSEncryptionContext=sent_b64,
    )
    assert "SSEKMSEncryptionContext" in put, f"PutObjectOutput omitted the context: {sorted(put)!r}"
    decoded = json.loads(base64.b64decode(put["SSEKMSEncryptionContext"]))
    expected = dict(sent_context, **{"aws:s3:arn": f"arn:aws:s3:::{bucket}/{good_key}"})
    assert decoded == expected, f"PutObject echoed context {decoded!r}, expected {expected!r}"
    assert put.get("SSEKMSKeyId") == key_arn, (
        f"PutObject reported key {put.get('SSEKMSKeyId')!r}, expected {key_arn!r}"
    )

    head = s3.head_object(Bucket=bucket, Key=good_key)
    head_headers = head["ResponseMetadata"]["HTTPHeaders"]
    assert _decoded(head_headers.get(_CONTEXT_HEADER)) == expected, (
        f"HeadObject must return the stored encryption context {expected!r}, "
        f"got {head_headers.get(_CONTEXT_HEADER)!r}"
    )
    assert head.get("SSEKMSKeyId") == key_arn, f"HeadObject reported key {head.get('SSEKMSKeyId')!r}"

    get = s3.get_object(Bucket=bucket, Key=good_key)
    try:
        assert get.get("SSEKMSKeyId") == key_arn, f"GetObject reported key {get.get('SSEKMSKeyId')!r}"
    finally:
        get["Body"].close()

    bad_key = "context-malformed.txt"
    bad_value = "not-valid-base64-json!!"
    code, message, arg_name, arg_value = _error(lambda: s3.put_object(
        Bucket=bucket, Key=bad_key, Body=b"payload",
        ServerSideEncryption="aws:kms", SSEKMSKeyId=key_id,
        SSEKMSEncryptionContext=bad_value,
    ))
    assert code == "InvalidArgument", f"a malformed context must be InvalidArgument, got {code!r}"
    assert message == _MALFORMED_MSG, f"unexpected message {message!r}"
    assert arg_name == "x-amz-server-side-encryption-context", f"unexpected ArgumentName {arg_name!r}"
    assert arg_value == bad_value, f"ArgumentValue echoed {arg_value!r}, expected {bad_value!r}"

    listed = _list_keys(s3, bucket)
    assert listed == [good_key], f"the refused write left the bucket listing {listed!r}"


def _create_bucket(ctx, s3, name: str) -> None:
    """Create a bucket in the target's region and register its teardown at once."""
    params: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    """Delete every object, then the bucket; raise on any failure but NoSuchBucket."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents") or []]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _list_keys(s3, bucket: str) -> list[str]:
    """Every key, paginated."""
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents") or [])
    return sorted(keys)


def _error(fn) -> tuple[str, str, str, str]:
    """(code, message, ArgumentName, ArgumentValue) of the ClientError fn() raises;
    raises AssertionError on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), err.get("ArgumentName"), err.get("ArgumentValue")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _decoded(header):
    """The JSON object a base64 encryption-context header carries, or None when absent."""
    return json.loads(base64.b64decode(header)) if header else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
