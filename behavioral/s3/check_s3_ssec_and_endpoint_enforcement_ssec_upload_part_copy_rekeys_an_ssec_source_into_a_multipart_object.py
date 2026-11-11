"""s3-ssec-and-endpoint-enforcement-ssec-upload-part-copy-rekeys-an-ssec-source-into-a-multipart-object."""

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

CHECK = (
    "s3-ssec-and-endpoint-enforcement-ssec-upload-part-copy-rekeys-an-ssec-source-into-a-multipart-object"
)
GROUP = "server_side_encryption"
SERVICES = ["s3"]

_MIB = 1024 * 1024


#: Exact S3 error messages.
_STORED_SSE = (
    "The object was stored using a form of Server Side Encryption. The correct parameters "
    "must be provided to retrieve the object."
)
_INITIATE_ENCRYPTED = (
    "The multipart upload initiate requested encryption. Subsequent part requests must "
    "include the appropriate encryption parameters."
)
_WRONG_SECRET = (
    "Requests specifying Server Side Encryption with Customer provided keys must provide the "
    "correct secret key."
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """UploadPartCopy re-keys ranges of an SSE-C source into an SSE-C multipart object: each copy
    needs the source key and the upload key, and the result answers only to the new key.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    _allow_ssec(s3, bucket)

    k_src, k_dst = os.urandom(32), os.urandom(32)
    src_sse = {"CopySourceSSECustomerAlgorithm": "AES256", "CopySourceSSECustomerKey": k_src}
    dst_sse = {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": k_dst}
    source = os.urandom(6 * _MIB)
    s3.put_object(Bucket=bucket, Key="source.bin", Body=source,
                  SSECustomerAlgorithm="AES256", SSECustomerKey=k_src)

    mpu = s3.create_multipart_upload(Bucket=bucket, Key="assembled.bin", **dst_sse)
    upload_id = mpu["UploadId"]
    ctx.on_cleanup(lambda: _abort_quietly(s3, bucket, "assembled.bin", upload_id))
    copy_source = {"Bucket": bucket, "Key": "source.bin"}
    first = f"bytes=0-{5 * _MIB - 1}"
    rest = f"bytes={5 * _MIB}-{len(source) - 1}"

    # --- Either key missing refuses the part copy.
    code, status, msg = _error(lambda: s3.upload_part_copy(
        Bucket=bucket, Key="assembled.bin", UploadId=upload_id, PartNumber=1,
        CopySource=copy_source, CopySourceRange=first, **dst_sse))
    assert (code, status, msg) == ("InvalidRequest", 400, _STORED_SSE), (
        f"UploadPartCopy without the SOURCE key returned {code!r}/{status!r} ({msg!r}); expected "
        "InvalidRequest/400"
    )
    code, status, msg = _error(lambda: s3.upload_part_copy(
        Bucket=bucket, Key="assembled.bin", UploadId=upload_id, PartNumber=1,
        CopySource=copy_source, CopySourceRange=first, **src_sse))
    assert (code, status, msg) == ("InvalidRequest", 400, _INITIATE_ENCRYPTED), (
        f"UploadPartCopy without the UPLOAD's key returned {code!r}/{status!r} ({msg!r}); expected "
        "InvalidRequest/400"
    )
    listed = s3.list_parts(Bucket=bucket, Key="assembled.bin", UploadId=upload_id).get("Parts", [])
    assert listed == [], f"the two refused part copies left parts behind: {listed!r}"

    # --- Both keys: the two ranges copy.
    r1 = s3.upload_part_copy(Bucket=bucket, Key="assembled.bin", UploadId=upload_id, PartNumber=1,
                             CopySource=copy_source, CopySourceRange=first, **dst_sse, **src_sse)
    r2 = s3.upload_part_copy(Bucket=bucket, Key="assembled.bin", UploadId=upload_id, PartNumber=2,
                             CopySource=copy_source, CopySourceRange=rest, **dst_sse, **src_sse)
    sizes = [(p["PartNumber"], p["Size"]) for p in s3.list_parts(
        Bucket=bucket, Key="assembled.bin", UploadId=upload_id).get("Parts", [])]
    assert sizes == [(1, 5 * _MIB), (2, _MIB)], f"ListParts after the copies: {sizes!r}"
    s3.complete_multipart_upload(
        Bucket=bucket, Key="assembled.bin", UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": r1["CopyPartResult"]["ETag"]},
                                   {"PartNumber": 2, "ETag": r2["CopyPartResult"]["ETag"]}]},
        **dst_sse,
    )

    # --- The result answers to the NEW key only.
    got = s3.get_object(Bucket=bucket, Key="assembled.bin", **dst_sse)["Body"].read()
    assert got == source, f"the assembled object ({len(got)} bytes) is not the source's plaintext"
    code, status, msg = _error(lambda: s3.get_object(
        Bucket=bucket, Key="assembled.bin", SSECustomerAlgorithm="AES256", SSECustomerKey=k_src))
    assert (code, status, msg) == ("AccessDenied", 403, _WRONG_SECRET), (
        f"reading the re-keyed object with the SOURCE's key returned {code!r}/{status!r} "
        f"({msg!r}); expected AccessDenied/403"
    )

    # --- And over raw HTTPS with the new key's signed headers.
    url = _presigner(ctx).generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": "assembled.bin", **dst_sse}, ExpiresIn=300)
    status, _, raw = _http("GET", url, headers={
        "x-amz-server-side-encryption-customer-algorithm": "AES256",
        "x-amz-server-side-encryption-customer-key": _b64(k_dst),
        "x-amz-server-side-encryption-customer-key-MD5": _b64(hashlib.md5(k_dst).digest()),
    })
    assert status == 200 and raw == source, (
        f"presigned SSE-C GET of the assembled object returned HTTP {status} ({len(raw)} bytes); "
        "expected 200 with the source's plaintext"
    )


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
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
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


def _error(fn):
    """(Error.Code, HTTP status, message) of the ClientError fn() raises. RAISES if fn succeeds."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
