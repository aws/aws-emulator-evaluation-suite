"""cors-preflight-for-presigned-put-with-unlisted-request-header-rejected."""
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

CHECK = "cors-preflight-for-presigned-put-with-unlisted-request-header-rejected"
GROUP = "cors"
SERVICES = ["s3"]

_ORIGIN = "https://app.example.com"
_KEY = "uploads/form.json"
_REFUSED = (
    "CORSResponse: This CORS request is not allowed. This is usually because the evalution of "
    "Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers "
    "are not whitelisted by the resource's CORS spec."
)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A PUT preflight asking for a request header the rule's AllowedHeaders omits is refused 403
    AccessForbidden with its exact message; asking for a listed header returns Allow-Headers.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_ORIGIN], "AllowedMethods": ["PUT"], "AllowedHeaders": ["content-type"],
    }]})
    url = _object_url(ctx, bucket, _KEY)

    # Positive control: the listed header is granted and echoed.
    _, headers, _ = _until_status(ctx, url, {
        "Origin": _ORIGIN, "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "content-type",
    }, 200)
    want = {
        "access-control-allow-origin": _ORIGIN,
        "access-control-allow-methods": "PUT",
        "access-control-allow-headers": "content-type",
        "access-control-allow-credentials": "true",
    }
    assert _cors(headers) == want, f"the granted preflight's CORS headers are {_cors(headers)!r}"

    status, headers, body = _http(ctx, "OPTIONS", url, {
        "Origin": _ORIGIN, "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "content-type,x-amz-meta-note",
    })
    assert status == 403, f"the preflight with an unlisted header answered {status}: {body[:300]!r}"
    err = ET.fromstring(body)
    got = (err.findtext("Code"), err.findtext("Message"), err.findtext("Method"),
           err.findtext("ResourceType"))
    assert got == ("AccessForbidden", _REFUSED, "PUT", "OBJECT"), (
        f"the refused preflight's (Code, Message, Method, ResourceType) is {got!r}"
    )
    assert _cors(headers) == {}, f"the refused preflight carries CORS headers {_cors(headers)!r}"

    # The refusal is the preflight's alone: the presigned PUT itself still stores the object.
    put_url = _signer(ctx).generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": _KEY}, ExpiresIn=300)
    status, _, body = _http(ctx, "PUT", put_url, {"Origin": _ORIGIN}, b"{}")
    assert status == 200, f"the presigned PUT answered {status}: {body[:300]!r}"
    got_body = s3.get_object(Bucket=bucket, Key=_KEY)["Body"].read()
    assert got_body == b"{}", f"GetObject reads {got_body!r} after the presigned PUT"


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
