"""s3-ssec-and-endpoint-enforcement-secure-transport-deny-policy-refuses-plaintext-http-and-allows-https."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "s3-ssec-and-endpoint-enforcement-secure-transport-deny-policy-refuses-plaintext-http-and-allows-https"
)
GROUP = "bucket_policy"
SERVICES = ["s3"]


#: Exact S3 error messages.
_NO_SUCH_KEY = "The specified key does not exist."


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A SecureTransport=false Deny policy refuses plaintext http:// read, list and write with
    an explicit-deny AccessDenied while each https:// twin is served; removing it restores http.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    body = b"served only over tls once the policy lands"
    s3.put_object(Bucket=bucket, Key="doc.txt", Body=body)
    signer = _presigner(ctx)
    get_url = signer.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": "doc.txt"}, ExpiresIn=600)
    list_url = signer.generate_presigned_url(
        "list_objects_v2", Params={"Bucket": bucket}, ExpiresIn=600)
    put_url = signer.generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": "written.txt"}, ExpiresIn=600)

    # Control: http:// is served before the policy, so the later 403 is attributable to it.
    status, _, raw = _http("GET", _as_http(get_url))
    assert status == 200 and raw == body, (
        f"control: http:// GET before the policy returned HTTP {status} {raw[:200]!r}; plaintext "
        "transport must work before the policy for the refusal to be attributable to it"
    )

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }],
    }))
    ctx.on_cleanup(lambda: s3.delete_bucket_policy(Bucket=bucket))

    # --- GET: http:// refused (polled — a policy is eventually consistent), https:// served.
    status, _, raw = _await(lambda: _http("GET", _as_http(get_url)), want=403)
    # message varies: each AccessDenied below names the runner's own identity ARN.
    assert _xml_code(raw) == "AccessDenied", (
        f"http:// GET under the SecureTransport Deny returned code {_xml_code(raw)!r}, expected "
        f"AccessDenied — body {raw[:300]!r}"
    )
    assert b"explicit deny" in raw, (
        f"the http:// refusal does not name the explicit deny: {raw[:400]!r}"
    )
    assert body not in raw, "the refused http:// GET leaked the object's bytes"
    status, _, raw = _http("GET", get_url)
    assert status == 200 and raw == body, (
        f"the https:// twin of the refused GET returned HTTP {status} {raw[:200]!r}; expected 200 "
        "with the object's bytes"
    )

    # --- LIST: http:// refused, https:// lists the key.
    status, _, raw = _http("GET", _as_http(list_url))
    assert status == 403 and _xml_code(raw) == "AccessDenied", (
        f"http:// ListObjectsV2 returned HTTP {status} code {_xml_code(raw)!r}; expected 403 "
        "AccessDenied"
    )
    status, _, raw = _http("GET", list_url)
    assert status == 200, f"https:// ListObjectsV2 returned HTTP {status}: {raw[:300]!r}"
    keys = [k.text for k in ET.fromstring(raw).iter() if k.tag.endswith("}Key") or k.tag == "Key"]
    assert keys == ["doc.txt"], f"https:// ListObjectsV2 listed {keys!r}, expected ['doc.txt']"

    # --- PUT: http:// refused with no effect, https:// lands.
    status, _, raw = _http("PUT", _as_http(put_url), data=b"plaintext write")
    assert status == 403 and _xml_code(raw) == "AccessDenied", (
        f"http:// PUT returned HTTP {status} code {_xml_code(raw)!r}; expected 403 AccessDenied"
    )
    code, _, msg = _error(lambda: s3.get_object(Bucket=bucket, Key="written.txt"))
    assert (code, msg) == ("NoSuchKey", _NO_SUCH_KEY), (
        f"the refused http:// PUT created an object ({code!r}: {msg!r})"
    )
    status, _, raw = _http("PUT", put_url, data=b"tls write")
    assert status == 200, f"the https:// twin of the refused PUT returned HTTP {status}: {raw[:300]!r}"
    got = s3.get_object(Bucket=bucket, Key="written.txt")["Body"].read()
    assert got == b"tls write", f"the https:// PUT read back as {got!r}"

    # --- Remove the statement: plaintext http:// is served again (the Deny, not the bucket, refused).
    s3.delete_bucket_policy(Bucket=bucket)
    status, _, raw = _await(lambda: _http("GET", _as_http(get_url)), want=200)
    assert raw == body, f"http:// GET after the policy was removed returned {raw[:200]!r}"


def _as_http(url: str) -> str:
    """The same URL with the scheme swapped to plaintext http. The SigV4 signature covers host,
    path, query and signed headers — not the scheme — so this is the exact twin request."""
    parts = urlsplit(url)
    assert parts.scheme == "https", f"expected an https URL to downgrade, got {url.split('?')[0]!r}"
    return parts._replace(scheme="http").geturl()


def _await(fetch, *, want: int, budget_s: float = 90.0):
    """Repeat fetch() until it answers HTTP `want`; RAISES with the last answer at the deadline."""
    deadline = time.monotonic() + budget_s
    last = fetch()
    while last[0] != want and time.monotonic() < deadline:
        time.sleep(3.0)
        last = fetch()
    assert last[0] == want, (
        f"never answered HTTP {want} within {budget_s:.0f}s; last was HTTP {last[0]} "
        f"{last[2][:300]!r}"
    )
    return last


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
