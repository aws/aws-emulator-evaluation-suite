"""s3-ssec-and-endpoint-enforcement-ssec-request-over-plain-http-rejected."""

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

CHECK = "s3-ssec-and-endpoint-enforcement-ssec-request-over-plain-http-rejected"
GROUP = "server_side_encryption"
SERVICES = ["s3"]


#: Exact S3 error messages, measured on real AWS.
_INSECURE_SSEC = (
    "Requests specifying Server Side Encryption with Customer provided keys must be made over "
    "a secure connection."
)
_NO_SUCH_KEY = "The specified key does not exist."


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """S3 refuses an SSE-C request over plaintext HTTP with InvalidArgument and writes nothing, while the
    byte-identical presigned request over HTTPS succeeds and plain HTTP serves a non-SSE-C object:
    the transport alone decides, with no bucket policy involved.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    _allow_ssec(s3, bucket)

    key = os.urandom(32)
    md5 = _b64(hashlib.md5(key).digest())
    sse = {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": key}
    hdrs = {
        "x-amz-server-side-encryption-customer-algorithm": "AES256",
        "x-amz-server-side-encryption-customer-key": _b64(key),
        "x-amz-server-side-encryption-customer-key-MD5": md5,
    }
    secret = os.urandom(4096)
    plain = b"plaintext-transport-control"
    s3.put_object(Bucket=bucket, Key="ssec.bin", Body=secret, **sse)
    s3.put_object(Bucket=bucket, Key="plain.txt", Body=plain)
    signer = _presigner(ctx)

    # --- Control 1: plaintext HTTP to this bucket works at all (no SSE-C involved).
    plain_url = signer.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": "plain.txt"}, ExpiresIn=300)
    status, _, raw = _http("GET", _as_http(plain_url))
    assert status == 200 and raw == plain, (
        f"control: presigned GET of a non-SSE-C object over http:// returned HTTP {status} "
        f"{raw[:200]!r}; plaintext transport must work for the refusal below to mean anything"
    )

    # --- The refusal: the SSE-C GET over http://.
    get_url = signer.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": "ssec.bin", **sse}, ExpiresIn=300)
    assert urlsplit(get_url).scheme == "https", f"presigned URL is not https: {get_url.split('?')[0]!r}"
    status, _, raw = _http("GET", _as_http(get_url), headers=hdrs)
    assert (status, _xml_code(raw), _xml_message(raw)) == (400, "InvalidArgument", _INSECURE_SSEC), (
        f"SSE-C GET over http:// returned HTTP {status} code {_xml_code(raw)!r}; expected 400 "
        f"InvalidArgument — body {raw[:300]!r}"
    )
    assert secret[:64] not in raw, "the refused plaintext SSE-C GET leaked object bytes"

    # --- Control 2: the identical URL and headers over https:// are served byte-exact.
    status, _, raw = _http("GET", get_url, headers=hdrs)
    assert status == 200 and raw == secret, (
        f"the https:// twin of the refused GET returned HTTP {status} ({len(raw)} bytes); expected "
        f"200 with the {len(secret)} stored bytes"
    )

    # --- The refusal on the write path, with the effect absent.
    put_url = signer.generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": "over-http.bin", **sse}, ExpiresIn=300)
    status, _, raw = _http("PUT", _as_http(put_url), headers=hdrs, data=b"must not land")
    assert (status, _xml_code(raw), _xml_message(raw)) == (400, "InvalidArgument", _INSECURE_SSEC), (
        f"SSE-C PUT over http:// returned HTTP {status} code {_xml_code(raw)!r}; expected 400 "
        f"InvalidArgument — body {raw[:300]!r}"
    )
    code, _, msg = _error(lambda: s3.get_object(Bucket=bucket, Key="over-http.bin", **sse))
    assert (code, msg) == ("NoSuchKey", _NO_SUCH_KEY), (
        f"the refused plaintext SSE-C PUT created an object ({code!r}: {msg!r})"
    )

    # --- Control 3: the same PUT over https:// lands, and reads back under the key.
    status, _, raw = _http("PUT", put_url, headers=hdrs, data=b"landed over tls")
    assert status == 200, f"the https:// twin of the refused PUT returned HTTP {status}: {raw[:300]!r}"
    back = s3.get_object(Bucket=bucket, Key="over-http.bin", **sse)["Body"].read()
    assert back == b"landed over tls", f"the https:// SSE-C PUT read back as {back!r}"


def _as_http(url: str) -> str:
    """The same URL with the scheme swapped to plaintext http. The SigV4 signature covers host,
    path, query and signed headers — not the scheme — so this is the exact twin request."""
    parts = urlsplit(url)
    assert parts.scheme == "https", f"expected an https URL to downgrade, got {url.split('?')[0]!r}"
    return parts._replace(scheme="http").geturl()


# ===== helpers (self-contained) =====


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
    """(Error.Code, HTTP status, message) of the ClientError fn() raises. RAISES if fn succeeds,
    so an over-permissive target cannot pass off acceptance as a code mismatch."""
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
