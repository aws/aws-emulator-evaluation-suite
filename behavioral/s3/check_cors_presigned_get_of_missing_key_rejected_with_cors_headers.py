"""cors-presigned-get-of-missing-key-rejected-with-cors-headers."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-presigned-get-of-missing-key-rejected-with-cors-headers"
GROUP = "cors"
SERVICES = ["s3"]

_ORIGIN = "https://app.example.com"
_KEY = "docs/present.txt"
_MISSING = "docs/absent.txt"
_BODY = b"present"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A presigned GET from an allowed origin for a key that does not exist answers 404 NoSuchKey
    with its exact message and still carries the matching rule's CORS headers, so a browser can read it.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY, ContentType="text/plain")
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_ORIGIN], "AllowedMethods": ["GET"], "ExposeHeaders": ["ETag"],
        "MaxAgeSeconds": 60,
    }]})
    _until_status(ctx, _object_url(ctx, bucket, _KEY),
                  {"Origin": _ORIGIN, "Access-Control-Request-Method": "GET"}, 200)
    signer = _signer(ctx)
    want = {
        "access-control-allow-origin": _ORIGIN,
        "access-control-allow-methods": "GET",
        "access-control-expose-headers": "ETag",
        "access-control-max-age": "60",
        "access-control-allow-credentials": "true",
    }

    # Positive control: the present key is served with the same headers.
    url = signer.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": _KEY},
                                        ExpiresIn=300)
    status, headers, body = _http(ctx, "GET", url, {"Origin": _ORIGIN})
    assert (status, body) == (200, _BODY), f"the present key answered {status}: {body[:300]!r}"
    assert _cors(headers) == want, f"the present key's CORS headers are {_cors(headers)!r}"

    url = signer.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": _MISSING},
                                        ExpiresIn=300)
    status, headers, body = _http(ctx, "GET", url, {"Origin": _ORIGIN})
    assert status == 404, f"the missing key answered {status}: {body[:300]!r}"
    err = ET.fromstring(body)
    got = (err.findtext("Code"), err.findtext("Message"), err.findtext("Key"))
    assert got == ("NoSuchKey", "The specified key does not exist.", _MISSING), (
        f"the missing key's error (Code, Message, Key) is {got!r}"
    )
    assert _cors(headers) == want, (
        f"the 404's CORS headers are {_cors(headers)!r}, expected {want!r}"
    )
    assert _tokens(headers.get("vary")) == {"origin", "access-control-request-headers", "access-control-request-method"}, f"the 404's Vary is {headers.get('vary')!r}"


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
