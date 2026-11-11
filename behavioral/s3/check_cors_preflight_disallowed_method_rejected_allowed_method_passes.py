"""cors-preflight-disallowed-method-rejected-allowed-method-passes."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from xml.etree import ElementTree

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-preflight-disallowed-method-rejected-allowed-method-passes"
GROUP = "cors"
SERVICES = ["s3"]

_ORIGIN = "https://app.example.com"
_KEY = "spa/assets/data.json"
_NOT_ALLOWED = (
    "AccessForbidden",
    "CORSResponse: This CORS request is not allowed. This is usually because the evalution of "
    "Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers "
    "are not whitelisted by the resource's CORS spec.",
)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A preflight requesting a method no CORS rule allows is refused 403 AccessForbidden with no
    Access-Control-* headers; the same origin requesting an allowed method still passes.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_KEY, Body=b'{"ok": true}', ContentType="application/json")
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_ORIGIN],
        "AllowedMethods": ["GET", "PUT"],
        "AllowedHeaders": ["*"],
        "MaxAgeSeconds": 600,
    }]})
    url = _object_url(ctx, bucket, _KEY)

    # Positive control: the allowed origin and method pass, so a target that refuses every
    # preflight cannot pass the refusals below.
    status, headers, body = _until_status(
        ctx, url, {"Origin": _ORIGIN, "Access-Control-Request-Method": "PUT"}, 200)
    assert status == 200, f"the allowed preflight must answer 200, got {status}: {body[:300]!r}"
    assert headers.get("access-control-allow-origin") == _ORIGIN, (
        f"the allowed preflight's Allow-Origin is {headers.get('access-control-allow-origin')!r}"
    )

    request_headers = {"Origin": _ORIGIN, "Access-Control-Request-Method": "DELETE"}
    status, headers, body = _http(ctx, "OPTIONS", url, request_headers)
    assert status == 403, f"the disallowed-method preflight must answer 403, got {status}: {body[:300]!r}"
    got = _xml_error(body)
    want = (*_NOT_ALLOWED, request_headers["Access-Control-Request-Method"], "OBJECT")
    assert got == want, f"the disallowed-method preflight's error is {got!r}, expected {want!r}"
    leaked = sorted(k for k in headers if k.startswith("access-control-"))
    assert leaked == [], f"the disallowed-method refusal carries CORS headers {leaked!r}"


def _xml_error(body):
    """(Code, Message, Method, ResourceType) of an S3 XML error body."""
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError as exc:
        raise AssertionError(f"the refusal body is not S3 XML: {body[:300]!r}") from exc
    return tuple(root.findtext(name) for name in ("Code", "Message", "Method", "ResourceType"))


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
