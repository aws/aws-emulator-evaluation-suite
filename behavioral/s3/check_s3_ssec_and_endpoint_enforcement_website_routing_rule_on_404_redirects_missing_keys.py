"""s3-ssec-and-endpoint-enforcement-website-routing-rule-on-404-redirects-missing-keys."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-ssec-and-endpoint-enforcement-website-routing-rule-on-404-redirects-missing-keys"
GROUP = "website_config"
SERVICES = ["s3"]

_PAGE = b"<!doctype html><p>a page that exists</p>"
_FALLBACK = b"<!doctype html><p>fallback for anything missing</p>"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A website RoutingRule on HttpErrorCodeReturnedEquals=404 redirects only missing keys, only on
    the website endpoint; a KeyPrefixEquals rule substitutes its prefix, and REST ignores both.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    # Only requests carrying this per-run secret as Referer may read the bucket's objects.
    referer = secrets.token_urlsafe(32)
    _make_public_read(s3, bucket, referer)
    s3.put_object(Bucket=bucket, Key="index.html", Body=b"<p>index</p>", ContentType="text/html")
    s3.put_object(Bucket=bucket, Key="page.html", Body=_PAGE, ContentType="text/html")
    s3.put_object(Bucket=bucket, Key="fallback.html", Body=_FALLBACK, ContentType="text/html")

    s3.put_bucket_website(Bucket=bucket,
                          WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}})
    base = _website_base_url(ctx, bucket, referer)

    # --- Control: with no rule, the website endpoint answers a missing key with a plain 404.
    _await(lambda: _http(ctx, referer, "GET", f"{base}/page.html"), want=200)
    status, headers, _ = _http(ctx, referer, "GET", f"{base}/missing.html")
    assert status == 404 and "location" not in headers, (
        f"control: before any RoutingRule, website GET /missing.html returned HTTP {status} "
        f"Location {headers.get('location')!r}; expected a plain 404"
    )

    rules = [
        {"Condition": {"KeyPrefixEquals": "docs/"},
         "Redirect": {"ReplaceKeyPrefixWith": "documents/"}},
        {"Condition": {"HttpErrorCodeReturnedEquals": "404"},
         "Redirect": {"ReplaceKeyWith": "fallback.html", "HttpRedirectCode": "302"}},
    ]
    s3.put_bucket_website(Bucket=bucket, WebsiteConfiguration={
        "IndexDocument": {"Suffix": "index.html"}, "RoutingRules": rules})
    stored = s3.get_bucket_website(Bucket=bucket).get("RoutingRules")
    assert stored == rules, f"GetBucketWebsite returned RoutingRules {stored!r}, expected {rules!r}"

    # --- The 404 rule fires: 302 to the absolute fallback URL on the website host, no body.
    status, headers, raw = _await(lambda: _http(ctx, referer, "GET", f"{base}/missing.html"), want=302)
    assert headers.get("location") == f"{base}/fallback.html", (
        f"website GET /missing.html redirected to {headers.get('location')!r}, expected "
        f"{base + '/fallback.html'!r}"
    )
    status, headers, _ = _http(ctx, referer, "GET", f"{base}/deeper/still-missing.html")
    assert status == 302 and headers.get("location") == f"{base}/fallback.html", (
        f"website GET of a nested missing key returned HTTP {status} Location "
        f"{headers.get('location')!r}; expected 302 to {base + '/fallback.html'!r}"
    )
    status, _, raw = _http(ctx, referer, "GET", headers["location"])
    assert status == 200 and raw == _FALLBACK, (
        f"following the redirect returned HTTP {status} {raw[:200]!r}; expected the fallback page"
    )

    # --- It does NOT fire for a key that exists.
    status, headers, raw = _http(ctx, referer, "GET", f"{base}/page.html")
    assert status == 200 and raw == _PAGE and "location" not in headers, (
        f"website GET of an EXISTING key under the 404 rule returned HTTP {status} Location "
        f"{headers.get('location')!r}; expected 200 with the page bytes"
    )

    # --- The prefix rule matches on the request key and substitutes the prefix (default 301).
    status, headers, _ = _http(ctx, referer, "GET", f"{base}/docs/guide.html")
    assert status == 301 and headers.get("location") == f"{base}/documents/guide.html", (
        f"website GET /docs/guide.html returned HTTP {status} Location {headers.get('location')!r};"
        f" expected 301 to {base + '/documents/guide.html'!r}"
    )

    # --- The REST endpoint ignores routing rules: the same missing key is NoSuchKey, not a redirect.
    code, status, msg = _error(lambda: s3.get_object(Bucket=bucket, Key="missing.html"))
    assert (code, status) == ("NoSuchKey", 404), (
        f"REST GetObject of the missing key returned {code!r}/{status!r} ({msg!r}); expected "
        "NoSuchKey/404 — routing rules are a website-endpoint behaviour"
    )
    assert msg == "The specified key does not exist.", msg


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
