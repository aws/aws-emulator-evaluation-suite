"""s3-ssec-and-endpoint-enforcement-ssec-multipart-upload-round-trips-only-with-the-customer-key."""

from __future__ import annotations

import base64
import hashlib
import os
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-ssec-and-endpoint-enforcement-ssec-multipart-upload-round-trips-only-with-the-customer-key"
GROUP = "server_side_encryption"
SERVICES = ["s3"]

_PART_1 = 5 * 1024 * 1024  # the minimum size of every part but the last
_PART_2 = 1234


#: Exact S3 error messages.
_STORED_SSE = (
    "The object was stored using a form of Server Side Encryption. The correct parameters "
    "must be provided to retrieve the object."
)
_PARAMS_MISMATCH = "The provided encryption parameters did not match the ones used originally."
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
    """An SSE-C multipart upload reassembles byte-exact; every part and read needs the initiate
    call's key (SDK and presigned raw HTTPS), while ListParts metadata needs no key.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    _allow_ssec(s3, bucket)

    key = os.urandom(32)
    other_key = os.urandom(32)
    md5 = _b64(hashlib.md5(key).digest())
    sse = {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": key}
    obj = "ssec-multipart.bin"
    part1 = os.urandom(_PART_1)
    part2 = os.urandom(_PART_2)

    mpu = s3.create_multipart_upload(Bucket=bucket, Key=obj, **sse)
    upload_id = mpu["UploadId"]
    ctx.on_cleanup(lambda: _abort_quietly(s3, bucket, obj, upload_id))
    assert mpu.get("SSECustomerAlgorithm") == "AES256", (
        f"CreateMultipartUpload echoed SSECustomerAlgorithm {mpu.get('SSECustomerAlgorithm')!r}, "
        "expected 'AES256'"
    )
    assert mpu.get("SSECustomerKeyMD5") == md5, (
        f"CreateMultipartUpload echoed key MD5 {mpu.get('SSECustomerKeyMD5')!r}, expected {md5!r}"
    )

    # --- The initiate call's key binds every part: no key, or another key, is refused.
    code, status, msg = _error(lambda: s3.upload_part(
        Bucket=bucket, Key=obj, UploadId=upload_id, PartNumber=1, Body=part2))
    assert (code, status, msg) == ("InvalidRequest", 400, _INITIATE_ENCRYPTED), (
        f"UploadPart with no SSE-C key into an SSE-C upload returned {code!r}/{status!r} ({msg!r}); "
        "expected InvalidRequest/400"
    )
    code, status, msg = _error(lambda: s3.upload_part(
        Bucket=bucket, Key=obj, UploadId=upload_id, PartNumber=1, Body=part2,
        SSECustomerAlgorithm="AES256", SSECustomerKey=other_key))
    assert (code, status, msg) == ("InvalidRequest", 400, _PARAMS_MISMATCH), (
        f"UploadPart with a DIFFERENT SSE-C key returned {code!r}/{status!r} ({msg!r}); expected "
        "InvalidRequest/400"
    )

    e1 = s3.upload_part(Bucket=bucket, Key=obj, UploadId=upload_id, PartNumber=1, Body=part1, **sse)
    e2 = s3.upload_part(Bucket=bucket, Key=obj, UploadId=upload_id, PartNumber=2, Body=part2, **sse)
    for n, e in ((1, e1), (2, e2)):
        assert e.get("SSECustomerKeyMD5") == md5, (
            f"UploadPart {n} echoed key MD5 {e.get('SSECustomerKeyMD5')!r}, expected {md5!r}"
        )

    # AWS serves ListParts without (or with a wrong) customer key: only part bytes are protected.
    # The two refused UploadParts above left nothing behind: exactly the two good parts are listed.
    listed = s3.list_parts(Bucket=bucket, Key=obj, UploadId=upload_id)
    sizes = [(p["PartNumber"], p["Size"]) for p in listed.get("Parts", [])]
    assert sizes == [(1, _PART_1), (2, _PART_2)], (
        f"ListParts without the key listed {sizes!r}; expected [(1, {_PART_1}), (2, {_PART_2})]"
    )

    done = s3.complete_multipart_upload(
        Bucket=bucket, Key=obj, UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e1["ETag"]},
                                   {"PartNumber": 2, "ETag": e2["ETag"]}]},
        **sse,
    )
    assert done["ETag"].strip('"').endswith("-2"), (
        f"CompleteMultipartUpload ETag {done['ETag']!r} does not carry the 2-part suffix"
    )

    # --- Read WITH the key: byte-exact reassembly, and the key is echoed back.
    got = s3.get_object(Bucket=bucket, Key=obj, **sse)
    body = got["Body"].read()
    assert body == part1 + part2, (
        f"GetObject with the key returned {len(body)} bytes that are not the concatenated parts "
        f"({_PART_1 + _PART_2} bytes)"
    )
    assert got.get("SSECustomerAlgorithm") == "AES256" and got.get("SSECustomerKeyMD5") == md5, (
        f"GetObject echoed SSE-C {got.get('SSECustomerAlgorithm')!r}/{got.get('SSECustomerKeyMD5')!r}"
        f", expected 'AES256'/{md5!r}"
    )
    p2 = s3.get_object(Bucket=bucket, Key=obj, PartNumber=2, **sse)["Body"].read()
    assert p2 == part2, f"GetObject PartNumber=2 returned {len(p2)} bytes that are not part 2"

    # --- Read WITHOUT the key, and with the WRONG key: refused, distinctly.
    code, status, msg = _error(lambda: s3.get_object(Bucket=bucket, Key=obj))
    assert (code, status, msg) == ("InvalidRequest", 400, _STORED_SSE), (
        f"GetObject without the key returned {code!r}/{status!r} ({msg!r}); expected "
        "InvalidRequest/400"
    )
    code, status, msg = _error(lambda: s3.get_object(
        Bucket=bucket, Key=obj, SSECustomerAlgorithm="AES256", SSECustomerKey=other_key))
    assert (code, status, msg) == ("AccessDenied", 403, _WRONG_SECRET), (
        f"GetObject with the wrong key returned {code!r}/{status!r} ({msg!r}); expected "
        "AccessDenied/403"
    )

    # The same two reads over raw HTTPS; the presigned signature covers the three SSE-C headers.
    signer = _presigner(ctx)
    hdrs = {
        "x-amz-server-side-encryption-customer-algorithm": "AES256",
        "x-amz-server-side-encryption-customer-key": _b64(key),
        "x-amz-server-side-encryption-customer-key-MD5": md5,
    }
    url = signer.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": obj, **sse}, ExpiresIn=300)
    assert urlsplit(url).scheme == "https", f"presigned URL {url.split('?')[0]!r} is not https"
    status, _, raw = _http("GET", url, headers=hdrs)
    assert status == 200, f"presigned SSE-C GET with the key headers returned HTTP {status}: {raw[:300]!r}"
    assert raw == part1 + part2, (
        f"presigned SSE-C GET returned {len(raw)} bytes that are not the concatenated parts"
    )
    plain_url = signer.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": obj}, ExpiresIn=300)
    status, _, raw = _http("GET", plain_url)
    assert (status, _xml_code(raw), _xml_message(raw)) == (400, "InvalidRequest", _STORED_SSE), (
        f"presigned GET with no SSE-C headers returned HTTP {status} code {_xml_code(raw)!r}; "
        f"expected 400 InvalidRequest — body {raw[:300]!r}"
    )
    assert part1[:64] not in raw, "the keyless raw GET leaked object bytes"


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
