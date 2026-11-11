"""cors-preflight-allowed-origin-returns-rule-headers."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-preflight-allowed-origin-returns-rule-headers"
GROUP = "cors"
SERVICES = ["s3"]

_ORIGIN = "https://app.example.com"
_KEY = "spa/assets/data.json"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A browser preflight matching a CORS rule gets 200 with the rule's origin, methods, requested
    headers, Max-Age, Expose-Headers, credentials and Vary, and an empty body.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_KEY, Body=b'{"ok": true}', ContentType="application/json")
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_ORIGIN],
        "AllowedMethods": ["GET", "PUT"],
        "AllowedHeaders": ["content-type", "x-amz-meta-note"],
        "ExposeHeaders": ["ETag", "x-amz-meta-note"],
        "MaxAgeSeconds": 3000,
    }]})

    url = _object_url(ctx, bucket, _KEY)
    status, headers, body = _until_status(ctx, url, {
        "Origin": _ORIGIN,
        "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "content-type,x-amz-meta-note",
    }, 200)
    assert status == 200, f"the matching preflight must answer 200, got {status}: {body[:300]!r}"
    got = {name: headers.get(name) for name in _CORS_HEADERS}
    want = {
        "access-control-allow-origin": _ORIGIN,
        "access-control-allow-methods": "GET, PUT",
        "access-control-allow-headers": "content-type, x-amz-meta-note",
        "access-control-max-age": "3000",
        "access-control-expose-headers": "ETag, x-amz-meta-note",
        "access-control-allow-credentials": "true",
    }
    assert got == want, f"the preflight's CORS headers are {got!r}, expected {want!r}"
    vary = _tokens(headers.get("vary"))
    assert vary == {"origin", "access-control-request-headers", "access-control-request-method"}, (
        f"the preflight's Vary is {headers.get('vary')!r}"
    )
    assert body == b"", f"a preflight answer carries no body, got {body[:300]!r}"


_CORS_HEADERS = (
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-max-age",
    "access-control-expose-headers",
    "access-control-allow-credentials",
)


def _tokens(value):
    """The lower-cased, comma-separated tokens of a header value."""
    return {t.strip().lower() for t in (value or "").split(",") if t.strip()}


def _object_url(ctx, bucket, key):
    """The unsigned object URL a browser fetches."""
    return ctx.s3_object_url(
        f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{urllib.parse.quote(key)}", bucket, key
    )


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, method, url, headers):
    """(status, lower-cased headers, body) of a raw request; an HTTP error status is returned."""
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60, context=_ssl_context(ctx.http_verify)) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _until_status(ctx, url, headers, want, budget_s=30.0):
    """The answer of a preflight to ``url`` once it is ``want`` (a CORS configuration change
    propagates); raises with the last answer when the budget runs out."""
    left = ctx.time_left()
    if left is not None:
        # Leave the check room to fail with its own message before the runner stops it.
        budget_s = min(budget_s, left / 3)
    deadline = time.monotonic() + budget_s
    while True:
        status, headers_got, body = _http(ctx, "OPTIONS", url, headers)
        if status == want:
            return status, headers_got, body
        if time.monotonic() > deadline:
            raise AssertionError(
                f"the preflight with {headers!r} answered {status}, not {want}, for {budget_s:.0f}s: "
                f"{body[:300]!r}"
            )
        time.sleep(2)


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; teardown only."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket; register empty+delete teardown; return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
