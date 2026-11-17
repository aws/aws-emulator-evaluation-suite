"""cors-preflight-without-a-request-method-header-rejected."""
from __future__ import annotations

import time
import urllib.parse
from xml.etree import ElementTree

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-preflight-without-a-request-method-header-rejected"
GROUP = "cors"
SERVICES = ["s3"]

_SITE = "https://shop.example.com"
_OBJECT_KEY = "catalogue/page-1.json"
_OBJECT_BODY = b'{"items": []}'


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A preflight that carries Origin but omits Access-Control-Request-Method is refused with
    its exact code and message, while the same preflight naming the allowed method answers 200.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors-troubleshooting.html
    """
    s3 = ctx.client("s3")
    bucket = _make_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_OBJECT_KEY, Body=_OBJECT_BODY,
                  ContentType="application/json")
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_SITE],
        "AllowedMethods": ["GET"],
        "AllowedHeaders": ["content-type"],
    }]})

    browser_url = _browser_url(ctx, bucket, _OBJECT_KEY)
    complete = {"Origin": _SITE, "Access-Control-Request-Method": "GET"}

    # The grant has to be in effect before the omission can be blamed for anything.
    granted = _await_preflight_grant(ctx, browser_url, complete)
    assert granted["headers"].get("access-control-allow-methods") == "GET", (
        "the complete preflight answered Access-Control-Allow-Methods "
        f"{granted['headers'].get('access-control-allow-methods')!r}, expected 'GET'"
    )

    headless = _send(ctx, "OPTIONS", browser_url, {"Origin": _SITE})
    assert headless["status"] == 403, (
        f"the preflight without a requested method answered {headless['status']!r}, expected 403: "
        f"{headless['body'][:300]!r}"
    )
    refusal = _refusal(headless["body"])
    # S3's refusal text verbatim, including its own wording; the check grades the exact message.
    expected = (
        "AccessForbidden",
        "CORSResponse: This CORS request is not allowed. This is usually because the evalution of "
        "Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers "
        "are not whitelisted by the resource's CORS spec.",
    )
    assert refusal == expected, (
        f"the preflight without a requested method was refused as {refusal!r}, expected {expected!r}"
    )
    granted_headers = sorted(k for k in headless["headers"] if k.startswith("access-control-"))
    assert granted_headers == [], (
        f"the refused preflight still carried CORS headers {granted_headers!r}"
    )

    # The rule is untouched, so the method-bearing preflight must still be granted.
    again = _send(ctx, "OPTIONS", browser_url, complete)
    assert again["status"] == 200, (
        f"the complete preflight answered {again['status']!r} after the refusal, expected 200: "
        f"{again['body'][:300]!r}"
    )
    assert again["headers"].get("access-control-allow-origin") == _SITE, (
        "the complete preflight answered Access-Control-Allow-Origin "
        f"{again['headers'].get('access-control-allow-origin')!r}, expected {_SITE!r}"
    )


def _refusal(body: bytes) -> tuple:
    """(Code, Message) carried by an S3 XML error document."""
    try:
        document = ElementTree.fromstring(body)
    except ElementTree.ParseError as exc:
        raise AssertionError(f"the refusal is not an S3 XML document: {body[:300]!r}") from exc
    return document.findtext("Code"), document.findtext("Message")


def _browser_url(ctx, bucket: str, key: str) -> str:
    """The object URL a page's script addresses, with no signature on it."""
    aws_form = f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{urllib.parse.quote(key)}"
    return ctx.s3_object_url(aws_form, bucket, key)


def _send(ctx, method: str, url: str, headers: dict) -> dict:
    """{status, headers, body} of one raw request; a 4xx answer is returned, not raised."""
    answer = requests.request(method, url, headers=headers, timeout=60,
                              verify=ctx.http_verify, allow_redirects=True)
    return {"status": answer.status_code,
            "headers": {n.lower(): v for n, v in answer.headers.items()},
            "body": answer.content}


def _await_preflight_grant(ctx, url: str, headers: dict, budget_s: float = 40.0) -> dict:
    """The preflight answer once it is a 200; raises with the last one when the budget is spent."""
    remaining = ctx.time_left()
    if remaining is not None:
        # Keep room for the check's own failure message instead of the runner's timeout.
        budget_s = min(budget_s, remaining / 3)
    give_up_at = time.monotonic() + budget_s
    while True:
        answer = _send(ctx, "OPTIONS", url, headers)
        if answer["status"] == 200:
            return answer
        if time.monotonic() > give_up_at:
            raise AssertionError(
                f"the preflight was still answering {answer['status']!r} after {budget_s:.0f}s, "
                f"never 200: {answer['body'][:300]!r}"
            )
        time.sleep(2)


def _purge(s3, bucket: str) -> None:
    """Delete every object in the bucket and then the bucket; a failed delete raises."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for stored in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=stored["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _make_bucket(ctx, s3) -> str:
    """Create a tagged bucket of this check's own, register its removal, return its name."""
    name = ctx.unique_name("sim2real-behav-cors-")
    arguments = {"Bucket": name}
    # A bucket is region-pinned, and us-east-1 is the one region S3 refuses as a
    # LocationConstraint, so the member is sent everywhere else and left out there.
    if ctx.region != "us-east-1":
        arguments["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**arguments)
    ctx.on_cleanup(lambda: _purge(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
