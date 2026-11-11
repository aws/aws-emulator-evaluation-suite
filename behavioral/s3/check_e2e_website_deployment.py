"""e2e-website-deployment."""

from __future__ import annotations

import json
import secrets
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "e2e-website-deployment"
GROUP = 'e2e_workflows'
SERVICES = ['s3']

# A target with no website data plane reads like a broken network ("Connection refused", "Read timed
# out"), so a URLError -- nothing listening at all -- is reported with this sentinel as a failure.
# HTTPError is deliberately NOT sentinelled: a 4xx/5xx means something DID answer.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# Website endpoints use the dash form in regions that predate the dotted convention.
_LEGACY_DASH_REGIONS = {
    "us-east-1", "us-west-1", "us-west-2", "eu-west-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1",
}


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_public_website_bucket(ctx, s3, referer):
    """Create a uniquely-named bucket configured for static website hosting, readable anonymously
    by requests whose Referer is `referer`.

    A Referer-conditioned grant still counts as public, so only BlockPublicPolicy and
    RestrictPublicBuckets are lifted; the ACL blocks stay on.
    """
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))

    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{name}/*",
                "Condition": {"StringEquals": {"aws:Referer": referer}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
    s3.put_bucket_website(
        Bucket=name,
        WebsiteConfiguration={
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "error.html"},
        },
    )
    return name


def _http_get(url, referer, timeout=10):
    """Raw, unsigned HTTP GET carrying `referer`; returns (status, lowercased-headers, body-bytes).
    4xx captured."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, method="GET", headers={"Referer": referer})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body
    except urllib.error.URLError as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: nothing answered at the S3 website endpoint {url} ({exc.reason}) -- "
            "the website data plane is absent, which is a fidelity failure and not a network fault"
        ) from exc


def _poll_get(url, referer, ready, timeout_s=60.0, interval_s=3.0):
    """Bounded retry: the public-read policy and website config are eventually consistent
    immediately after being set, so the first fetch after deployment may lag by a few seconds."""
    deadline = time.monotonic() + timeout_s
    result = (None, {}, b"")
    while time.monotonic() < deadline:
        result = _http_get(url, referer)
        if ready(*result):
            return result
        time.sleep(interval_s)
    return result


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The S3 website endpoint serves the index document at the root, the configured error document for
    a missing key, and a non-index key with its stored content-type: routing the S3 API cannot show.
    """
    s3 = ctx.client("s3")
    # Only requests carrying this per-run secret as Referer may read the website's objects.
    referer = secrets.token_urlsafe(32)
    bucket = _new_public_website_bucket(ctx, s3, referer)
    html_body = b"<!DOCTYPE html><html><body><h1>Hello</h1></body></html>"
    error_body = b"<!DOCTYPE html><html><body><h1>Not Found</h1></body></html>"
    css_body = b"body { font-family: sans-serif; }"

    s3.put_object(Bucket=bucket, Key="index.html", Body=html_body, ContentType="text/html")
    s3.put_object(Bucket=bucket, Key="error.html", Body=error_body, ContentType="text/html")
    s3.put_object(Bucket=bucket, Key="style.css", Body=css_body, ContentType="text/css")

    if ctx.region in _LEGACY_DASH_REGIONS:
        aws = f"http://{bucket}.s3-website-{ctx.region}.amazonaws.com"
    else:
        aws = f"http://{bucket}.s3-website.{ctx.region}.amazonaws.com"
    endpoint = ctx.s3_website_urls([aws], bucket)[0]

    # Root path resolves the configured IndexDocument — a plain object store has no notion of
    # "index document at /"; this is website-endpoint routing, not GetObject.
    status, headers, body = _poll_get(f"{endpoint}/", referer, lambda s, h, b: s == 200)
    assert status == 200, f"expected 200 for website root, got {status}: {body[:300]!r}"
    assert body == html_body, f"expected index.html body at website root, got {body!r}"
    assert headers.get("content-type", "").startswith("text/html"), (
        f"expected text/html content-type at website root, got {headers.get('content-type')!r}"
    )

    # A missing key must be answered by the CONFIGURED error document body, with the standing
    # HTTP status still 404 — not the default S3 XML error page.
    status, headers, body = _http_get(f"{endpoint}/does-not-exist.html", referer)
    assert status == 404, f"expected 404 for a missing key via the website endpoint, got {status}"
    assert body == error_body, f"expected the configured error document body, got {body!r}"

    # A non-index key round-trips its own stored content-type through the website endpoint.
    status, headers, body = _http_get(f"{endpoint}/style.css", referer)
    assert status == 200, f"expected 200 for style.css via the website endpoint, got {status}"
    assert body == css_body, f"expected style.css body, got {body!r}"
    assert headers.get("content-type", "").startswith("text/css"), (
        f"expected text/css content-type for style.css, got {headers.get('content-type')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
