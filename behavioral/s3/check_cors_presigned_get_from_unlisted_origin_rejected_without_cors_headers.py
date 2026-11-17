"""cors-presigned-get-from-unlisted-origin-rejected-without-cors-headers."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-presigned-get-from-unlisted-origin-rejected-without-cors-headers"
GROUP = "cors"
SERVICES = ["s3"]

_ALLOWED = "https://app.example.com"
_OTHER = "https://other.example.net"
_KEY = "docs/readme.txt"
_BODY = b"hello from the bucket"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A presigned GET from an origin no CORS rule lists is served but carries no Access-Control-*
    header and no Vary, while the same URL from the listed origin carries the rule's headers.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY, ContentType="text/plain")
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_ALLOWED], "AllowedMethods": ["GET"],
    }]})
    _until_status(ctx, _object_url(ctx, bucket, _KEY),
                  {"Origin": _ALLOWED, "Access-Control-Request-Method": "GET"}, 200)
    url = _signer(ctx).generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": _KEY}, ExpiresIn=300)

    # Positive control: the listed origin is granted on the same URL.
    status, headers, body = _http(ctx, "GET", url, {"Origin": _ALLOWED})
    assert status == 200, f"the presigned GET from the listed origin answered {status}: {body[:300]!r}"
    want = {
        "access-control-allow-origin": _ALLOWED,
        "access-control-allow-methods": "GET",
        "access-control-allow-credentials": "true",
    }
    assert _cors(headers) == want, (
        f"the listed origin's CORS headers are {_cors(headers)!r}, expected {want!r}"
    )
    assert _tokens(headers.get("vary")) == {"origin", "access-control-request-headers", "access-control-request-method"}, (
        f"the listed origin's Vary is {headers.get('vary')!r}"
    )

    status, headers, body = _http(ctx, "GET", url, {"Origin": _OTHER})
    assert status == 200, f"the presigned GET from an unlisted origin answered {status}: {body[:300]!r}"
    assert body == _BODY, f"the presigned GET from an unlisted origin served {body[:300]!r}"
    assert _cors(headers) == {}, (
        f"the unlisted origin must get no Access-Control-* header, got {_cors(headers)!r}"
    )
    assert "vary" not in headers, f"the unlisted origin's answer has Vary {headers.get('vary')!r}"


def _cors(headers):
    """The Access-Control-* headers of a response."""
    return {k: v for k, v in headers.items() if k.startswith("access-control-")}


def _tokens(value):
    """The lower-cased, comma-separated tokens of a header value."""
    return {t.strip().lower() for t in (value or "").split(",") if t.strip()}


def _signer(ctx):
    """A SigV4 S3 client that presigns path-style URLs."""
    return ctx.client("s3", config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))


def _object_url(ctx, bucket, key):
    """The unsigned object URL a browser fetches."""
    return ctx.s3_object_url(
        f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{urllib.parse.quote(key)}", bucket, key
    )


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, method, url, headers, data=None):
    """(status, lower-cased headers, body) of a raw request; an HTTP error status is returned."""
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
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
