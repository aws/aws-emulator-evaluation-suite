"""cors-preflight-refused-after-delete-bucket-cors."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from xml.etree import ElementTree

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-preflight-refused-after-delete-bucket-cors"
GROUP = "cors"
SERVICES = ["s3"]

_ORIGIN = "https://app.example.com"
_KEY = "spa/assets/data.json"
_PREFLIGHT = {"Origin": _ORIGIN, "Access-Control-Request-Method": "GET"}


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A preflight a CORS rule allowed is refused 403 "CORS is not enabled for this bucket." once
    DeleteBucketCors removes the configuration, while the object itself stays readable.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_KEY, Body=b'{"ok": true}', ContentType="application/json")
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_ORIGIN], "AllowedMethods": ["GET"],
    }]})
    url = _object_url(ctx, bucket, _KEY)

    # Positive control: the rule allows the preflight before the delete.
    status, headers, body = _until_status(ctx, url, _PREFLIGHT, 200)
    assert status == 200, f"the preflight before DeleteBucketCors must answer 200, got {status}: {body[:300]!r}"
    assert headers.get("access-control-allow-origin") == _ORIGIN, (
        f"the preflight before DeleteBucketCors has Allow-Origin {headers.get('access-control-allow-origin')!r}"
    )

    s3.delete_bucket_cors(Bucket=bucket)
    code, message = _error_code(lambda: s3.get_bucket_cors(Bucket=bucket))
    assert (code, message) == ("NoSuchCORSConfiguration", "The CORS configuration does not exist"), (
        f"GetBucketCors after DeleteBucketCors answered {(code, message)!r}"
    )

    status, headers, body = _until_status(ctx, url, _PREFLIGHT, 403)
    assert status == 403, f"the preflight after DeleteBucketCors must answer 403, got {status}: {body[:300]!r}"
    got = _xml_error(body)
    want = ("AccessForbidden", "CORSResponse: CORS is not enabled for this bucket.", "GET", "BUCKET")
    assert got == want, f"the preflight after DeleteBucketCors was refused with {got!r}, expected {want!r}"
    leaked = sorted(k for k in headers if k.startswith("access-control-"))
    assert leaked == [], f"the refusal carries CORS headers {leaked!r}"
    read = s3.get_object(Bucket=bucket, Key=_KEY)["Body"].read()
    assert read == b'{"ok": true}', f"the object reads {read!r} after DeleteBucketCors"


def _error_code(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call succeeded where an error was expected")


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
