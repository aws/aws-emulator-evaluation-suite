"""ssec-head-object-requires-the-matching-customer-key."""
from __future__ import annotations

import base64
import hashlib
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssec-head-object-requires-the-matching-customer-key"
GROUP = "server_side_encryption"
SERVICES = ["s3"]

#: botocore falls back to the generic HTTP reason phrase for a HEAD error body.
_NO_BODY_400 = "400", "Bad Request"
_NO_BODY_403 = "403", "Forbidden"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """HeadObject on an SSE-C object needs the object's customer key: absent is refused 400,
    wrong is refused 403, and the right key echoes SSECustomerAlgorithm and its key MD5."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    _allow_ssec(s3, bucket)

    key_bytes = os.urandom(32)
    other_key_bytes = os.urandom(32)
    md5 = _b64(hashlib.md5(key_bytes).digest())
    sse = {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": key_bytes}
    obj = "ssec-head.bin"
    body = b"ssec-head-object-body"

    put = s3.put_object(Bucket=bucket, Key=obj, Body=body, **sse)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=obj))
    assert put.get("SSECustomerAlgorithm") == "AES256", (
        f"PutObject echoed SSECustomerAlgorithm {put.get('SSECustomerAlgorithm')!r}, "
        "expected 'AES256'"
    )
    assert put.get("SSECustomerKeyMD5") == md5, (
        f"PutObject echoed key MD5 {put.get('SSECustomerKeyMD5')!r}, expected {md5!r}"
    )

    # --- No key: refused 400, with the generic HTTP reason (HEAD carries no error body).
    code, status, msg = _error(lambda: s3.head_object(Bucket=bucket, Key=obj))
    assert (code, status, msg) == (_NO_BODY_400[0], 400, _NO_BODY_400[1]), (
        f"HeadObject without the key returned {code!r}/{status!r} ({msg!r}); expected "
        f"{_NO_BODY_400[0]!r}/400 ({_NO_BODY_400[1]!r})"
    )

    # --- Wrong key: refused 403, distinctly from the missing-key case.
    code, status, msg = _error(lambda: s3.head_object(
        Bucket=bucket, Key=obj, SSECustomerAlgorithm="AES256", SSECustomerKey=other_key_bytes))
    assert (code, status, msg) == (_NO_BODY_403[0], 403, _NO_BODY_403[1]), (
        f"HeadObject with the wrong key returned {code!r}/{status!r} ({msg!r}); expected "
        f"{_NO_BODY_403[0]!r}/403 ({_NO_BODY_403[1]!r})"
    )

    # --- Positive control: the right key succeeds and echoes the algorithm and key MD5.
    head = s3.head_object(Bucket=bucket, Key=obj, **sse)
    assert head.get("SSECustomerAlgorithm") == "AES256", (
        f"HeadObject with the right key reported SSECustomerAlgorithm "
        f"{head.get('SSECustomerAlgorithm')!r}, expected 'AES256'"
    )
    assert head.get("SSECustomerKeyMD5") == md5, (
        f"HeadObject with the right key reported key MD5 {head.get('SSECustomerKeyMD5')!r}, "
        f"expected {md5!r}"
    )


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _error(fn):
    """(Error.Code, HTTP status, message) of the ClientError fn() raises. RAISES if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                exc.response.get("Error", {}).get("Message"))
    raise AssertionError(f"expected the call to be refused and it succeeded: {result!r}")


def _delete_bucket(client, bucket):
    """Abort uploads, empty every version, delete the bucket. TEARDOWN ONLY."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
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
        client.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket; register empty+delete teardown; return its name."""
    name = ctx.unique_name("sim2real-s3edge-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK[:256]}]},
    )
    return name


def _allow_ssec(s3, bucket):
    """Opt THIS bucket out of the SSE-C upload block and assert the opt-out is what is stored."""
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={"Rules": [{
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
            "BlockedEncryptionTypes": {"EncryptionType": ["NONE"]},
        }]},
    )
    rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    blocked = rules[0].get("BlockedEncryptionTypes", {}).get("EncryptionType")
    assert blocked == ["NONE"], f"bucket still blocks {blocked!r} after the SSE-C opt-out"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
