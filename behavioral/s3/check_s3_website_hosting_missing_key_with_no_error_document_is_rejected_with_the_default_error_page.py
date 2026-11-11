"""s3-website-hosting-missing-key-with-no-error-document-is-rejected-with-the-default-error-page."""

from __future__ import annotations

import json
import secrets
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-website-hosting-missing-key-with-no-error-document-is-rejected-with-the-default-error-page"
GROUP = "website_config"
SERVICES = ["s3"]

_INDEX = b"<!doctype html><title>root index</title><p>root</p>"


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A website-endpoint GET of a missing key, with no ErrorDocument configured, is rejected
    with S3's own default HTML 404 page naming Code NoSuchKey and its exact Message.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    referer = secrets.token_urlsafe(32)
    # The missing key is granted too: an ungranted key answers 403 whether or not it exists, so
    # the 404 default error page only appears for a key the policy actually covers.
    _grant_public_read(s3, bucket, public_keys=["index.html", "this-key-does-not-exist.html"],
                       referer=referer)

    s3.put_object(Bucket=bucket, Key="index.html", Body=_INDEX, ContentType="text/html")
    s3.put_bucket_website(Bucket=bucket,
                          WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}})
    got_cfg = s3.get_bucket_website(Bucket=bucket)
    assert "ErrorDocument" not in got_cfg, (
        f"GetBucketWebsite reports an ErrorDocument {got_cfg.get('ErrorDocument')!r}; this check "
        "needs none configured so the default error page is the one under test"
    )

    base = _website_base_url(ctx, bucket, referer)

    # --- Positive control: the website endpoint is live and serving the index document.
    _await(ctx, lambda: _http(ctx, referer, "GET", f"{base}/"), want=200)

    status, headers, body = _await(ctx,
        lambda: _http(ctx, referer, "GET", f"{base}/this-key-does-not-exist.html"), want=404
    )
    text = body.decode("utf-8", errors="replace")
    assert "html" in headers.get("content-type", "").lower(), (
        f"the missing-key 404 carried Content-Type {headers.get('content-type')!r}; expected an "
        "HTML error page"
    )
    assert "<?xml" not in text, (
        f"the missing-key 404 returned an XML error body: {text[:300]!r} — the website endpoint "
        "must answer with its own HTML error page, not the REST endpoint's XML"
    )
    assert "<h1>404 Not Found</h1>" in text, (
        f"the default error page is missing the <h1>404 Not Found</h1> heading: {text[:500]!r}"
    )
    assert "<li>Code: NoSuchKey</li>" in text, (
        f"the default error page is missing the documented Code line for NoSuchKey: {text[:500]!r}"
    )
    assert "<li>Message: The specified key does not exist.</li>" in text, (
        f"the default error page is missing the documented Message line: {text[:500]!r}"
    )

    # --- REST twin, same instant: the same missing key is a plain XML NoSuchKey, not an HTML page.
    code, status_rest, msg = _error(lambda: s3.get_object(Bucket=bucket, Key="this-key-does-not-exist.html"))
    assert (code, status_rest) == ("NoSuchKey", 404), (
        f"REST GetObject of the same missing key returned {code!r}/{status_rest!r} ({msg!r}); "
        "expected NoSuchKey/404"
    )
    assert msg == "The specified key does not exist.", msg


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


def _error(fn):
    """(Error.Code, HTTP status, message) of the ClientError fn() raises. RAISES if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                exc.response.get("Error", {}).get("Message"))
    raise AssertionError("the call was expected to be refused and it succeeded")


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
    """Raw HTTP carrying `referer`; returns (status, lowercased headers, body).

    3xx/4xx/5xx are answers, not errors."""
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, method=method, data=data, headers=route_headers)
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
