"""s3-ssec-and-endpoint-enforcement-ssec-copy-to-sse-s3-without-the-copy-source-key-rejected."""

from __future__ import annotations

import base64
import hashlib
import os
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-ssec-and-endpoint-enforcement-ssec-copy-to-sse-s3-without-the-copy-source-key-rejected"
GROUP = "server_side_encryption"
SERVICES = ["s3"]


#: Exact S3 error messages.
_STORED_SSE = (
    "The object was stored using a form of Server Side Encryption. The correct parameters "
    "must be provided to retrieve the object."
)
_PARAMS_MISMATCH = "The provided encryption parameters did not match the ones used originally."
_NOT_APPLICABLE = "The encryption parameters are not applicable to this object."
_NO_SUCH_KEY = "The specified key does not exist."


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """CopyObject from an SSE-C source to SSE-S3 is refused (400 InvalidRequest) without the right
    CopySource customer key and creates nothing; with it, the copy is re-encrypted as SSE-S3,
    readable keyless, and refuses the old customer key as inapplicable.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    _allow_ssec(s3, bucket)

    key = os.urandom(32)
    src, dst = "ssec-source.bin", "sse-s3-copy.bin"
    payload = os.urandom(64 * 1024)
    s3.put_object(Bucket=bucket, Key=src, Body=payload,
                  SSECustomerAlgorithm="AES256", SSECustomerKey=key)
    copy_source = {"Bucket": bucket, "Key": src}

    # --- Break exactly one thing: omit the source key.
    code, status, msg = _error(lambda: s3.copy_object(
        Bucket=bucket, Key=dst, CopySource=copy_source, ServerSideEncryption="AES256"))
    assert (code, status, msg) == ("InvalidRequest", 400, _STORED_SSE), (
        f"CopyObject from an SSE-C source WITHOUT CopySourceSSECustomerKey returned "
        f"{code!r}/{status!r} ({msg!r}); expected InvalidRequest/400"
    )
    code, _, msg = _error(lambda: s3.get_object(Bucket=bucket, Key=dst))
    assert (code, msg) == ("NoSuchKey", _NO_SUCH_KEY), (
        f"the refused copy left a destination object behind ({code!r}: {msg!r})"
    )

    # --- And a WRONG source key is refused the same way, also with no effect.
    code, status, msg = _error(lambda: s3.copy_object(
        Bucket=bucket, Key=dst, CopySource=copy_source, ServerSideEncryption="AES256",
        CopySourceSSECustomerAlgorithm="AES256", CopySourceSSECustomerKey=os.urandom(32)))
    assert (code, status, msg) == ("InvalidRequest", 400, _PARAMS_MISMATCH), (
        f"CopyObject with the WRONG CopySourceSSECustomerKey returned {code!r}/{status!r} "
        f"({msg!r}); expected InvalidRequest/400"
    )
    code, _, msg = _error(lambda: s3.get_object(Bucket=bucket, Key=dst))
    assert (code, msg) == ("NoSuchKey", _NO_SUCH_KEY), (
        f"the wrong-key copy left a destination object behind ({code!r}: {msg!r})"
    )

    # --- Positive control, same request plus the source key: succeeds and re-encrypts as SSE-S3.
    done = s3.copy_object(
        Bucket=bucket, Key=dst, CopySource=copy_source, ServerSideEncryption="AES256",
        CopySourceSSECustomerAlgorithm="AES256", CopySourceSSECustomerKey=key)
    assert done.get("ServerSideEncryption") == "AES256", (
        f"the keyed copy reported ServerSideEncryption {done.get('ServerSideEncryption')!r}, "
        "expected 'AES256' (SSE-S3)"
    )
    assert done.get("SSECustomerAlgorithm") is None, (
        f"the SSE-S3 destination still claims SSE-C ({done.get('SSECustomerAlgorithm')!r})"
    )
    head = s3.head_object(Bucket=bucket, Key=dst)
    assert head.get("ServerSideEncryption") == "AES256" and head.get("SSECustomerAlgorithm") is None, (
        f"HeadObject(dst) reports SSE {head.get('ServerSideEncryption')!r} / SSE-C "
        f"{head.get('SSECustomerAlgorithm')!r}; expected AES256 / None"
    )
    assert head["ContentLength"] == len(payload), (
        f"destination is {head['ContentLength']} bytes, source was {len(payload)}"
    )

    # --- The destination is readable with NO customer key, over a raw presigned HTTPS GET.
    signer = _presigner(ctx)
    url = signer.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": dst},
                                        ExpiresIn=300)
    status, headers, raw = _http("GET", url)
    assert status == 200, f"presigned GET of the SSE-S3 copy returned HTTP {status}: {raw[:300]!r}"
    assert raw == payload, "the SSE-S3 copy's bytes differ from the SSE-C source's plaintext"
    assert headers.get("x-amz-server-side-encryption") == "AES256", (
        f"raw GET reported x-amz-server-side-encryption "
        f"{headers.get('x-amz-server-side-encryption')!r}, expected 'AES256'"
    )

    # --- ...while offering the old customer key on the copy is now refused as inapplicable,
    # and the SOURCE still needs its key (the copy did not decrypt it in place).
    code, status, msg = _error(lambda: s3.get_object(
        Bucket=bucket, Key=dst, SSECustomerAlgorithm="AES256", SSECustomerKey=key))
    assert (code, status, msg) == ("InvalidRequest", 400, _NOT_APPLICABLE), (
        f"GetObject(dst) WITH the old customer key returned {code!r}/{status!r} ({msg!r}); "
        "expected InvalidRequest/400 — the copy is not SSE-C any more"
    )
    src_url = signer.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": src},
                                            ExpiresIn=300)
    status, _, raw = _http("GET", src_url)
    assert (status, _xml_code(raw), _xml_message(raw)) == (400, "InvalidRequest", _STORED_SSE), (
        f"keyless raw GET of the SSE-C SOURCE returned HTTP {status} code {_xml_code(raw)!r} "
        f"message {_xml_message(raw)!r}; expected 400 InvalidRequest {_STORED_SSE!r}"
    )
    assert payload[:64] not in raw, "the keyless raw GET of the source leaked its bytes"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


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


def _abort_quietly(client, bucket, key, upload_id):
    try:
        client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError:
        pass  # already completed: CompleteMultipartUpload consumed the upload id


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


def _error(fn):
    """(Error.Code, HTTP status, message) of the ClientError fn() raises; a success fails."""
    try:
        fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                exc.response.get("Error", {}).get("Message"))
    raise AssertionError("the call was expected to be refused and it succeeded")


def _presigner(ctx):
    """A SigV4 presigning S3 client, path-style so every target is sent one request shape."""
    return ctx.client("s3", config=Config(signature_version="s3v4",
                                          s3={"addressing_style": "path"}))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # a 3xx is an answer to assert on, never something to follow


_OPENER = urllib.request.build_opener(_NoRedirect)


def _http(method, url, headers=None, data=None):
    """Raw HTTP; returns (status, lowercased headers, body). 3xx/4xx/5xx are answers, not errors."""
    req = urllib.request.Request(url, method=method, data=data)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with _OPENER.open(req, timeout=60) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _xml_code(body: bytes):
    """The <Code> of an S3 XML error body, or None when the body is not one."""
    try:
        node = ET.fromstring(body).find("Code")
    except ET.ParseError:
        return None
    return node.text if node is not None else None


def _xml_message(body: bytes):
    """The <Message> of an S3 XML error body, or None when the body is not one."""
    try:
        node = ET.fromstring(body).find("Message")
    except ET.ParseError:
        return None
    return node.text if node is not None else None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
