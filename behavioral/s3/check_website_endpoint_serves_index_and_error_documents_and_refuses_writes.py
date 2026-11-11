"""website-endpoint-serves-index-and-error-documents-and-refuses-writes."""

from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "website-endpoint-serves-index-and-error-documents-and-refuses-writes"
GROUP = "website_config"
SERVICES = ["s3"]

_INDEX = b"<!doctype html><title>root index</title><p>root</p>"
_SUB_INDEX = b"<!doctype html><title>sub index</title><p>sub</p>"
_ERROR_DOC = b"<!doctype html><title>custom error</title><p>not here</p>"
_PRIVATE = b"this object is explicitly denied to anonymous callers"


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """The S3 website endpoint serves `/` and `sub/` as their index documents, a missing key as the custom
    error document with 404, an ungranted key with 403 and a PUT with 405 that writes nothing, while the
    REST endpoint lists the keys at the bucket root and answers the missing key with NoSuchKey."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    # The missing key "definitely-not-here.html" is granted too: S3 answers an anonymous GET for a
    # key the policy does not cover with 403 whether or not it exists, so the error document's 404
    # only appears for an authorized key. The grant requires a per-run secret Referer.
    referer = secrets.token_urlsafe(32)
    _make_public_read_except(
        s3,
        bucket,
        public_keys=["index.html", "sub/index.html", "error.html", "definitely-not-here.html"],
        referer=referer,
    )
    with_referer = {"Referer": referer}

    s3.put_object(Bucket=bucket, Key="index.html", Body=_INDEX, ContentType="text/html")
    s3.put_object(Bucket=bucket, Key="sub/index.html", Body=_SUB_INDEX, ContentType="text/html")
    s3.put_object(Bucket=bucket, Key="error.html", Body=_ERROR_DOC, ContentType="text/html")
    s3.put_object(Bucket=bucket, Key="private.txt", Body=_PRIVATE, ContentType="text/plain")

    s3.put_bucket_website(
        Bucket=bucket,
        WebsiteConfiguration={
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "error.html"},
        },
    )
    got_cfg = s3.get_bucket_website(Bucket=bucket)
    assert got_cfg["IndexDocument"]["Suffix"] == "index.html", (
        f"GetBucketWebsite reports index suffix {got_cfg['IndexDocument']!r}, expected index.html"
    )
    assert got_cfg["ErrorDocument"]["Key"] == "error.html", (
        f"GetBucketWebsite reports error document {got_cfg['ErrorDocument']!r}, expected error.html"
    )

    base = _website_base_url(ctx, bucket)

    # --- Leg 1: the root path serves the index document. On the REST endpoint the same path is a
    # key listing, which is the twin control below.
    status, headers, body = _await_http(ctx, f"{base}/", expect_status=200, headers=with_referer)
    assert body == _INDEX, (
        f"GET {base}/ returned {body[:200]!r}; the website endpoint must return the index "
        f"document's exact bytes ({_INDEX[:60]!r}...)"
    )
    assert "html" in headers.get("content-type", ""), (
        f"GET {base}/ returned Content-Type {headers.get('content-type')!r}; the index document was "
        "stored as text/html"
    )

    # --- Leg 2: a directory-shaped path appends the index suffix.
    status, _, body = _http(ctx, "GET", f"{base}/sub/", headers=with_referer)
    assert status == 200, f"GET {base}/sub/ returned {status}, expected 200"
    assert body == _SUB_INDEX, (
        f"GET {base}/sub/ returned {body[:200]!r}; expected the bytes of sub/index.html "
        f"({_SUB_INDEX[:60]!r}...) — the index suffix is not being appended to a prefix request"
    )

    # --- Leg 3: a missing key returns the CUSTOM ERROR DOCUMENT with a 404, not an XML error.
    status, _, body = _http(ctx, "GET", f"{base}/definitely-not-here.html", headers=with_referer)
    assert status == 404, (
        f"GET of a missing key on the website endpoint returned {status}, expected 404; body "
        f"{body[:200]!r}"
    )
    assert body == _ERROR_DOC, (
        f"GET of a missing key returned {body[:200]!r}; the website endpoint must return the "
        f"configured error document's exact bytes ({_ERROR_DOC[:60]!r}...), not an XML error"
    )
    assert b"<Error>" not in body and b"NoSuchKey" not in body, (
        f"the website endpoint returned an XML error body for a missing key: {body[:200]!r} — this "
        "is the REST endpoint's behaviour, so the website hostname is being served by the REST "
        "handler"
    )

    # --- Leg 4: only publicly readable content is served. private.txt exists and is byte-identical
    # to the three public keys in every respect except that the bucket policy never granted it.
    assert s3.get_object(Bucket=bucket, Key="private.txt")["Body"].read() == _PRIVATE, (
        "positive control: private.txt must be readable with credentials, otherwise the 403 below "
        "would only prove the key is missing"
    )
    status, _, body = _http(ctx, "GET", f"{base}/private.txt", headers=with_referer)
    assert status == 403, (
        f"GET of a key the bucket policy does not grant returned {status} on the website endpoint, "
        f"expected 403; body {body[:200]!r}"
    )
    assert _PRIVATE not in body, (
        "the website endpoint served the bytes of a key no policy statement grants anonymously"
    )

    # --- Leg 5: writes are refused. The website endpoint supports GET and HEAD only.
    status, _, body = _http(
        ctx, "PUT", f"{base}/written-via-website.txt", headers=with_referer, data=b"should not land"
    )
    assert status == 405, (
        f"PUT to the website endpoint returned {status}, expected 405 — the website endpoint "
        f"supports only GET and HEAD; body {body[:200]!r}"
    )
    # HeadObject has no body, so S3's answer is the bare status: botocore reports it as code "404"
    # with the HTTP reason phrase as the message.
    head_err = _error(lambda: s3.head_object(Bucket=bucket, Key="written-via-website.txt"))
    assert head_err == ("404", "Not Found", 404), (
        f"the key written-via-website.txt exists after a PUT the website endpoint refused: {head_err!r}"
    )

    # --- Twin control, same instant: the REST endpoint answers the SAME two paths differently.
    rest_root = s3.list_objects_v2(Bucket=bucket)
    rest_keys = {o["Key"] for o in rest_root.get("Contents", [])}
    assert rest_keys == {"index.html", "sub/index.html", "error.html", "private.txt"}, (
        f"the REST endpoint lists {sorted(rest_keys)} at the bucket root; expected the four keys "
        "this check created — the REST root must be a key listing while the website root is the "
        "index document"
    )
    get_err = _error(lambda: s3.get_object(Bucket=bucket, Key="definitely-not-here.html"))
    assert get_err == ("NoSuchKey", "The specified key does not exist.", 404), (
        f"the REST endpoint answered {get_err!r} for the same missing key the website endpoint "
        "answered with the error document; expected NoSuchKey"
    )


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it. TEARDOWN ONLY —
    never on an assertion path."""
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
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket; register empty+delete teardown; return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )
    return name


def _make_public_read_except(s3, bucket: str, *, public_keys: list[str], referer: str) -> None:
    """Grant anonymous s3:GetObject on exactly `public_keys` to requests whose Referer is `referer`;
    every other key stays private."""
    # S3 classifies a grant to "*" conditioned on aws:Referer as public, so only the two policy
    # settings are lifted; the ACL blocks stay on.
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicReadNamedKeysOnly",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": [f"arn:aws:s3:::{bucket}/{k}" for k in public_keys],
                    "Condition": {"StringEquals": {"aws:Referer": referer}},
                }
            ],
        }),
    )


def _error(fn) -> tuple:
    """(Error.Code, Error.Message, HTTP status) of the ClientError fn() raises; RAISES if fn
    succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
    raise AssertionError("the call was expected to fail and it succeeded")


def _http(ctx, method: str, url: str, headers=None, data=None):
    """Raw HTTP; returns (status, lowercased headers, body). 4xx/5xx are answers, not errors."""
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, method=method, data=data, headers=route_headers)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _website_base_url(ctx, bucket: str) -> str:
    """The bucket's website base URL, chosen from the documented candidate hostnames.

    AWS uses either "s3-website-Region" or "s3-website.Region" depending on the Region, so both are
    probed; if none answers the check fails."""
    # The documented website hosts, dot form first (HTTP-only: no SSL on AWS's website endpoints).
    candidates = ctx.s3_website_urls(
        [f"http://{bucket}.s3-website.{ctx.region}.amazonaws.com",
         f"http://{bucket}.s3-website-{ctx.region}.amazonaws.com"],
        bucket,
    )
    reachable = []
    for candidate in candidates:
        try:
            _http(ctx, "GET", f"{candidate}/")
        except urllib.error.URLError:
            # Discovery only: an unresolvable candidate is not this candidate. Never a skip — if
            # every candidate is unreachable the assert below fails the check.
            continue
        reachable.append(candidate)
    assert reachable, (
        f"none of the website endpoint candidates for bucket {bucket} could be reached: "
        f"{candidates} — the target publishes no S3 website endpoint"
    )
    return reachable[0]


def _await_http(ctx, url: str, *, expect_status: int, headers=None):
    """GET `url` until it answers `expect_status`, with a deadline. Website configuration can take a
    few seconds to become effective; this RAISES rather than returning its last answer."""
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        last = _http(ctx, "GET", url, headers=headers)
        if last[0] == expect_status:
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"GET {url} never returned {expect_status} within 90s; last answer was HTTP {last[0]} with "
        f"body {last[2][:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
