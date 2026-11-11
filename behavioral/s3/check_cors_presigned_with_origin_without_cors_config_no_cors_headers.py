"""cors-presigned-with-origin-without-cors-config-no-cors-headers."""
from __future__ import annotations

import hashlib
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-presigned-with-origin-without-cors-config-no-cors-headers"
GROUP = "cors"
SERVICES = ["s3"]

_ORIGIN = "https://app.example.com"
_KEY = "uploads/report.json"
_BODY = b'{"report": "quarterly", "rows": 3}'


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A presigned PUT and GET sent with a browser Origin to a bucket with no CORS configuration
    are served as ordinary requests with no Access-Control-* header or Vary; the same GET to a
    sibling bucket whose CORS rule allows the origin carries Allow-Origin.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
    """
    s3 = ctx.client("s3")
    signer = ctx.client("s3", config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))

    # Positive control: a sibling bucket whose CORS rule allows the origin answers the same
    # presigned GET with Allow-Origin, so a target that never emits CORS headers cannot pass.
    twin = _new_bucket(ctx, s3)
    s3.put_object(Bucket=twin, Key=_KEY, Body=_BODY, ContentType="application/json")
    s3.put_bucket_cors(Bucket=twin, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_ORIGIN], "AllowedMethods": ["GET"],
    }]})
    _until_status(ctx, _object_url(ctx, twin, _KEY),
                  {"Origin": _ORIGIN, "Access-Control-Request-Method": "GET"}, 200)
    twin_url = signer.generate_presigned_url(
        "get_object", Params={"Bucket": twin, "Key": _KEY}, ExpiresIn=300)
    status, headers, body = _http(ctx, "GET", twin_url, {"Origin": _ORIGIN})
    assert status == 200, f"the configured twin's presigned GET must answer 200, got {status}: {body[:300]!r}"
    assert headers.get("access-control-allow-origin") == _ORIGIN, (
        f"the configured twin's presigned GET has Allow-Origin {headers.get('access-control-allow-origin')!r}"
    )
    assert "origin" in {t.strip().lower() for t in headers.get("vary", "").split(",")}, (
        f"the configured twin's presigned GET has Vary {headers.get('vary')!r}"
    )

    bucket = _new_bucket(ctx, s3)
    put_url = signer.generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": _KEY, "ContentType": "application/json"},
        ExpiresIn=300)
    get_url = signer.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": _KEY}, ExpiresIn=300)
    md5 = hashlib.md5(_BODY).hexdigest()

    status, headers, body = _http(ctx, "PUT", put_url,
                                  {"Origin": _ORIGIN, "Content-Type": "application/json"}, _BODY)
    assert status == 200, f"the presigned PUT with Origin must answer 200, got {status}: {body[:300]!r}"
    assert headers.get("etag") == f'"{md5}"', f"the presigned PUT's ETag is {headers.get('etag')!r}"
    _assert_no_cors(headers, "PUT")

    status, headers, body = _http(ctx, "GET", get_url, {"Origin": _ORIGIN})
    assert status == 200, f"the presigned GET with Origin must answer 200, got {status}: {body[:300]!r}"
    assert body == _BODY, f"the presigned GET served {body[:300]!r}, expected {_BODY!r}"
    _assert_no_cors(headers, "GET")
    stored = s3.head_object(Bucket=bucket, Key=_KEY)
    assert (stored["ContentLength"], stored["ETag"]) == (len(_BODY), f'"{md5}"'), (
        f"HeadObject reads (ContentLength, ETag) {(stored['ContentLength'], stored['ETag'])!r}"
    )


def _assert_no_cors(headers, method):
    """Without a CORS configuration the response names no CORS header and no Vary."""
    got = sorted(k for k in headers if k.startswith("access-control-"))
    assert got == [], f"the presigned {method} without CORS configuration carries {got!r}"
    assert "vary" not in headers, f"the presigned {method}'s Vary is {headers.get('vary')!r}"


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
