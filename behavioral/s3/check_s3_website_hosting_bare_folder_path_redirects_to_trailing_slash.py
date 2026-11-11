"""s3-website-hosting-bare-folder-path-redirects-to-trailing-slash."""

from __future__ import annotations

import json
import secrets
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-website-hosting-bare-folder-path-redirects-to-trailing-slash"
GROUP = "website_config"
SERVICES = ["s3"]

_FOLDER_INDEX = b"<!doctype html><title>folder index</title><p>inside folder</p>"


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A website-endpoint GET of a key-prefix with no trailing slash, backed by a
    `<prefix>/index.html` object, answers 302 with Location `<prefix>/`; the REST endpoint
    answers the same bare path with NoSuchKey.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    referer = secrets.token_urlsafe(32)
    _grant_public_read(s3, bucket, public_keys=["folder/index.html"], referer=referer)

    s3.put_object(Bucket=bucket, Key="folder/index.html", Body=_FOLDER_INDEX,
                  ContentType="text/html")
    s3.put_bucket_website(Bucket=bucket,
                          WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}})
    base = _website_base_url(ctx, bucket, referer)

    status, headers, body = _await(ctx, lambda: _http(ctx, referer, "GET", f"{base}/folder"), want=302)
    assert headers.get("location") == "/folder/", (
        f"website GET {base}/folder returned HTTP {status} Location "
        f"{headers.get('location')!r}; expected a 302 to '/folder/'"
    )
    assert _FOLDER_INDEX not in body, (
        f"website GET {base}/folder (no trailing slash) served the folder index's bytes directly "
        f"instead of redirecting: {body[:200]!r}"
    )

    # --- Following the redirect serves the folder's index document.
    status, _, body = _await(ctx, lambda: _http(ctx, referer, "GET", f"{base}{headers['location']}"), want=200)
    assert status == 200 and body == _FOLDER_INDEX, (
        f"GET {base}{headers['location']} (the redirect target) returned HTTP {status} "
        f"{body[:200]!r}; expected 200 with the folder index bytes {_FOLDER_INDEX[:60]!r}..."
    )

    # --- REST twin, same instant: "folder" is not itself an object, so GetObject answers NoSuchKey
    # rather than any redirect.
    code, status_rest, msg = _error(lambda: s3.get_object(Bucket=bucket, Key="folder"))
    assert (code, status_rest) == ("NoSuchKey", 404), (
        f"REST GetObject of key 'folder' returned {code!r}/{status_rest!r} ({msg!r}); expected "
        "NoSuchKey/404 — the bare-folder redirect is a website-endpoint behaviour"
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
