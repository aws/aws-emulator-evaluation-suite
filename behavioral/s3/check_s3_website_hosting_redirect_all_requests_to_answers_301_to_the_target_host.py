"""s3-website-hosting-redirect-all-requests-to-answers-301-to-the-target-host."""

from __future__ import annotations

import json
import secrets
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-website-hosting-redirect-all-requests-to-answers-301-to-the-target-host"
GROUP = "website_config"
SERVICES = ["s3"]

_TARGET_INDEX = b"<!doctype html><title>target index</title><p>the real content</p>"
_TARGET_PAGE = b"<!doctype html><title>target page</title><p>a specific page</p>"


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A website bucket configured with RedirectAllRequestsTo answers every path with 301 to the
    target bucket's website host, preserving the request path, never serving its own content.
    """
    s3 = ctx.client("s3")
    target = _new_bucket(ctx, s3)
    source = _new_bucket(ctx, s3)
    referer = secrets.token_urlsafe(32)
    _grant_public_read(s3, target, public_keys=["index.html", "page.html"], referer=referer)

    s3.put_object(Bucket=target, Key="index.html", Body=_TARGET_INDEX, ContentType="text/html")
    s3.put_object(Bucket=target, Key="page.html", Body=_TARGET_PAGE, ContentType="text/html")
    s3.put_bucket_website(Bucket=target,
                          WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}})
    target_base = _website_base_url(ctx, target, referer)
    target_host = target_base.split("://", 1)[1]

    # The source bucket is never read anonymously: RedirectAllRequestsTo answers every request
    # from the redirect alone, so the source needs no public grant and no index document.
    s3.put_bucket_website(Bucket=source,
                          WebsiteConfiguration={"RedirectAllRequestsTo": {"HostName": target_host}})
    source_base = _source_website_base_url(ctx, source)

    # --- The bucket root redirects to the target host's root, preserving scheme and path.
    status, headers, _ = _await(ctx,
        lambda: _http(ctx, None, "GET", f"{source_base}/"), want=301
    )
    assert headers.get("location") == f"{target_base}/", (
        f"website GET {source_base}/ returned HTTP {status} Location "
        f"{headers.get('location')!r}; expected a 301 to {target_base + '/'!r}"
    )

    # --- A specific path is preserved across the redirect, including a path the source bucket
    # never held any object for — the redirect fires unconditionally, not only for missing keys.
    status, headers, _ = _http(ctx, None, "GET", f"{source_base}/page.html")
    assert status == 301 and headers.get("location") == f"{target_base}/page.html", (
        f"website GET {source_base}/page.html returned HTTP {status} Location "
        f"{headers.get('location')!r}; expected a 301 to {target_base + '/page.html'!r}"
    )
    status, headers, _ = _http(ctx, None, "GET", f"{source_base}/never-existed-anywhere.html")
    assert status == 301 and headers.get("location") == (
        f"{target_base}/never-existed-anywhere.html"
    ), (
        f"website GET of a key the target never held returned HTTP {status} Location "
        f"{headers.get('location')!r}; RedirectAllRequestsTo must redirect unconditionally, "
        "never answer its own 404"
    )

    # --- Following the redirect reaches the target bucket's real content.
    status, _, body = _await(ctx, lambda: _http(ctx, referer, "GET", f"{target_base}/page.html"), want=200)
    assert status == 200 and body == _TARGET_PAGE, (
        f"GET {target_base}/page.html (the redirect target) returned HTTP {status} "
        f"{body[:200]!r}; expected 200 with the target page bytes"
    )


def _grant_public_read(s3, bucket: str, *, public_keys: list[str], referer: str) -> None:
    """Anonymous s3:GetObject on exactly `public_keys`, conditioned on a per-run secret Referer."""
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                        "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Sid": "PublicReadNamedKeysOnly", "Effect": "Allow", "Principal": "*",
                       "Action": "s3:GetObject",
                       "Resource": [f"arn:aws:s3:::{bucket}/{k}" for k in public_keys],
                       "Condition": {"StringEquals": {"aws:Referer": referer}}}],
    }))


def _website_base_url(ctx, bucket: str, referer: str) -> str:
    """The bucket's website base URL, chosen from the documented candidate hostnames.

    TRANSPORT DERIVATION ONLY — no assertion forks on which candidate answered. AWS documents two
    hostname shapes ("s3-website dash Region" and "s3-website dot Region"); the dash form is tried
    first. A new website host can take a while to resolve, so discovery polls; if none answers, FAIL.
    """
    candidates = [f"http://{bucket}.s3-website-{ctx.region}.amazonaws.com",
                  f"http://{bucket}.s3-website.{ctx.region}.amazonaws.com"]
    budget_s = _budget_s(ctx, 90.0)
    deadline = time.monotonic() + budget_s
    while True:
        for candidate in candidates:
            try:
                _http(ctx, referer, "GET", f"{candidate}/")
            except urllib.error.URLError:
                continue
            return candidate
        if time.monotonic() > deadline:
            # A stable wrong answer is a failure; only a run out of budget is a timeout.
            raise (TimeoutError if ctx.time_left() is not None and ctx.time_left() <= 5 else AssertionError)(
                f"no S3 website endpoint candidate for {bucket} answered within {budget_s:.0f}s: {candidates}"
            )
        time.sleep(3.0)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _source_website_base_url(ctx, bucket: str) -> str:
    """The RedirectAllRequestsTo source bucket's website base URL.

    TRANSPORT DERIVATION ONLY. The source serves no content of its own — every request answers a
    redirect — so discovery probes for a 301 rather than a 200.
    """
    candidates = [f"http://{bucket}.s3-website-{ctx.region}.amazonaws.com",
                  f"http://{bucket}.s3-website.{ctx.region}.amazonaws.com"]
    budget_s = _budget_s(ctx, 90.0)
    deadline = time.monotonic() + budget_s
    while True:
        for candidate in candidates:
            try:
                status, _, _ = _http(ctx, None, "GET", f"{candidate}/")
            except urllib.error.URLError:
                continue
            if status == 301:
                return candidate
        if time.monotonic() > deadline:
            # A stable wrong answer is a failure; only a run out of budget is a timeout.
            raise (TimeoutError if ctx.time_left() is not None and ctx.time_left() <= 5 else AssertionError)(
                f"no S3 website endpoint candidate for {bucket} answered 301 within {budget_s:.0f}s: {candidates}"
            )
        time.sleep(3.0)


def _await(ctx, fetch, *, want: int, cap_s: float = 90.0):
    """Repeat fetch() until it answers HTTP `want`; a different stable answer fails the check."""
    budget_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + budget_s
    last = fetch()
    while last[0] != want:
        if time.monotonic() > deadline:
            # A stable wrong answer is a failure; only a run out of budget is a timeout.
            raise (TimeoutError if ctx.time_left() is not None and ctx.time_left() <= 5 else AssertionError)(
                f"never answered HTTP {want} within {budget_s:.0f}s; last was HTTP {last[0]} "
                f"{last[2][:300]!r}"
            )
        time.sleep(3.0)
        last = fetch()
    return last


def _delete_bucket(client, bucket):
    """Drop the bucket policy, empty every version, delete the bucket. TEARDOWN ONLY."""
    try:
        client.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchBucketPolicy"):
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
    """Create a uniquely-named, tagged bucket; register policy+object+bucket teardown."""
    name = ctx.unique_name("sim2real-s3site-")
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # a 3xx is an answer to assert on, never something to follow


def _opener(ctx):
    """A urllib opener that never follows a redirect and verifies TLS per ``ctx.http_verify``."""
    return urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=_ssl_context(ctx.http_verify))
    )


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, referer, method, url, headers=None, data=None):
    """Raw HTTP, optionally carrying `referer`; returns (status, lowercased headers, body).

    3xx/4xx/5xx are answers, not errors."""
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, method=method, data=data, headers=route_headers)
    if referer is not None:
        req.add_header("Referer", referer)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with _opener(ctx).open(req, timeout=60) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
