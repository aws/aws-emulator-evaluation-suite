"""s3-ssec-and-endpoint-enforcement-website-endpoint-serving-an-ssec-object-rejected."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-ssec-and-endpoint-enforcement-website-endpoint-serving-an-ssec-object-rejected"
GROUP = "website_config"
SERVICES = ["s3"]

_PLAIN = b"<!doctype html><p>plain public page</p>"
_SSEC_MESSAGE = (
    "The object was stored using a form of Server Side Encryption. "
    "The correct parameters must be provided to retrieve the object."
)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """The plaintext website endpoint refuses an SSE-C object with 400 InvalidRequest (HTML) and
    never its bytes; a plain object is served and the SSE-C object stays readable with its key.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    _allow_ssec(s3, bucket)
    # Only requests carrying this per-run secret as Referer may read the bucket's objects.
    referer = secrets.token_urlsafe(32)
    _make_public_read(s3, bucket, referer)

    key = os.urandom(32)
    secret = b"customer-encrypted bytes no anonymous caller may ever see " + os.urandom(64)
    s3.put_object(Bucket=bucket, Key="plain.html", Body=_PLAIN, ContentType="text/html")
    s3.put_object(Bucket=bucket, Key="index.html", Body=b"<p>index</p>", ContentType="text/html")
    s3.put_object(Bucket=bucket, Key="secret.html", Body=secret, ContentType="text/html",
                  SSECustomerAlgorithm="AES256", SSECustomerKey=key)
    s3.put_bucket_website(Bucket=bucket,
                          WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}})
    base = _website_base_url(ctx, bucket, referer)

    # --- Positive control: the same bucket and policy serve a plain object on the website.
    status, _, raw = _await(lambda: _http(ctx, referer, "GET", f"{base}/plain.html"), want=200)
    assert raw == _PLAIN, f"website GET /plain.html returned {raw[:200]!r}, expected its bytes"

    # --- The refusal on the website endpoint.
    status, headers, raw = _http(ctx, referer, "GET", f"{base}/secret.html")
    assert status == 400, (
        f"website GET of an SSE-C object returned HTTP {status}, expected 400 — body {raw[:300]!r}"
    )
    page = _html_error_fields(raw)
    assert page.get("Code") == "InvalidRequest", (
        f"the website endpoint's 400 page does not name InvalidRequest: {raw[:400]!r}"
    )
    assert page.get("Message") == _SSEC_MESSAGE, page.get("Message")
    assert secret[:40] not in raw, "the website endpoint served SSE-C object bytes anonymously"

    # --- The anonymous REST twin refuses the same way, as XML.
    rest = urlsplit(_presigner(ctx).generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": "secret.html"}, ExpiresIn=60))
    status, _, raw = _http(ctx, referer, "GET", rest._replace(query="").geturl())
    assert status == 400 and _xml_code(raw) == "InvalidRequest", (
        f"anonymous REST GET of the SSE-C object returned HTTP {status} code {_xml_code(raw)!r}; "
        "expected 400 InvalidRequest"
    )
    assert _xml_field(raw, "Message") == _SSEC_MESSAGE, _xml_field(raw, "Message")
    assert secret[:40] not in raw, "the anonymous REST GET served SSE-C object bytes"

    # --- Positive control: the object is intact and readable with its key over the signed API.
    got = s3.get_object(Bucket=bucket, Key="secret.html",
                        SSECustomerAlgorithm="AES256", SSECustomerKey=key)["Body"].read()
    assert got == secret, "the SSE-C object is not readable with its key"


def _make_public_read(s3, bucket: str, referer: str) -> None:
    """Anonymous s3:GetObject on this bucket's objects for requests whose Referer is `referer`.

    A Referer-conditioned grant still counts as public, so only BlockPublicPolicy and
    RestrictPublicBuckets are lifted; the ACL blocks stay on.
    """
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                        "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
                       "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
                       "Condition": {"StringEquals": {"aws:Referer": referer}}}],
    }))


def _website_base_url(ctx, bucket: str, referer: str) -> str:
    """The bucket's website base URL, chosen from the documented candidate hostnames.

    TRANSPORT DERIVATION ONLY — no assertion forks on which candidate answered. AWS documents two
    hostname shapes ("s3-website dash Region" and "s3-website dot Region"); the dash form is tried
    first. If none answers, FAIL.
    """
    # The documented website hosts, dash form first (HTTP-only: no SSL on AWS's website endpoints).
    candidates = ctx.s3_website_urls(
        [f"http://{bucket}.s3-website-{ctx.region}.amazonaws.com",
         f"http://{bucket}.s3-website.{ctx.region}.amazonaws.com"],
        bucket,
    )
    reachable = []
    for candidate in candidates:
        try:
            _http(ctx, referer, "GET", f"{candidate}/")
        except urllib.error.URLError:
            continue  # discovery only; if none is reachable the assert below fails the check
        reachable.append(candidate)
    assert reachable, f"no S3 website endpoint candidate for {bucket} answered: {candidates}"
    return reachable[0]


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


def _http(ctx, referer, method, url, headers=None, data=None):
    """Raw HTTP carrying `referer`; returns (status, lowercased headers, body).

    3xx/4xx/5xx are answers, not errors."""
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, method=method, data=data, headers=route_headers)
    req.add_header("Referer", referer)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with _OPENER.open(req, timeout=60) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _xml_field(body: bytes, field: str):
    """The <field> text of an S3 XML error body, or None when the body is not one."""
    try:
        node = ET.fromstring(body).find(field)
    except ET.ParseError:
        return None
    return node.text if node is not None else None


def _xml_code(body: bytes):
    """The <Code> of an S3 XML error body, or None when the body is not one."""
    return _xml_field(body, "Code")


def _html_error_fields(body: bytes) -> dict:
    """The `<li>Name: value</li>` fields of an S3 website HTML error page."""
    fields = {}
    for item in re.findall(r"<li>(.*?)</li>", body.decode("utf-8", "replace"), flags=re.S):
        name, sep, value = item.partition(": ")
        if sep:
            fields[name] = value
    return fields


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
