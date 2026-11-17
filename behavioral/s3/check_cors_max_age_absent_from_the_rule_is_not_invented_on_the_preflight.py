"""cors-max-age-absent-from-the-rule-is-not-invented-on-the-preflight."""
from __future__ import annotations

import time
import urllib.parse

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-max-age-absent-from-the-rule-is-not-invented-on-the-preflight"
GROUP = "cors"
SERVICES = ["s3"]

_SITE = "https://cache.example.com"
_OBJECT_KEY = "static/app.js"
_OBJECT_BODY = b"// a cross-origin script"
_CACHE_FOR_S = 3000


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A rule without MaxAgeSeconds leaves Access-Control-Max-Age off its preflight while the
    rest of the grant stands, where a rule that sets it answers that value on every matched request.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html
    """
    s3 = ctx.client("s3")
    timed = _make_bucket(ctx, s3)
    untimed = _make_bucket(ctx, s3)
    for bucket in (timed, untimed):
        s3.put_object(Bucket=bucket, Key=_OBJECT_KEY, Body=_OBJECT_BODY,
                      ContentType="application/javascript")
    s3.put_bucket_cors(Bucket=timed, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_SITE],
        "AllowedMethods": ["GET"],
        "AllowedHeaders": ["content-type"],
        "MaxAgeSeconds": _CACHE_FOR_S,
    }]})
    s3.put_bucket_cors(Bucket=untimed, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_SITE],
        "AllowedMethods": ["GET"],
        "AllowedHeaders": ["content-type"],
    }]})

    # The rule that sets the member is the legal neighbour of the one that leaves it out.
    with_member = _await_preflight(ctx, _unsigned_url(ctx, timed, _OBJECT_KEY))
    assert with_member.get("access-control-max-age") == str(_CACHE_FOR_S), (
        "the rule carrying MaxAgeSeconds answered Access-Control-Max-Age "
        f"{with_member.get('access-control-max-age')!r}, expected {str(_CACHE_FOR_S)!r}"
    )

    without_member = _await_preflight(ctx, _unsigned_url(ctx, untimed, _OBJECT_KEY))
    assert without_member.get("access-control-allow-origin") == _SITE, (
        "the rule without MaxAgeSeconds answered Access-Control-Allow-Origin "
        f"{without_member.get('access-control-allow-origin')!r}, expected {_SITE!r}"
    )
    assert without_member.get("access-control-allow-methods") == "GET", (
        "the rule without MaxAgeSeconds answered Access-Control-Allow-Methods "
        f"{without_member.get('access-control-allow-methods')!r}, expected 'GET'"
    )
    assert "access-control-max-age" not in without_member, (
        "the rule without MaxAgeSeconds still answered Access-Control-Max-Age "
        f"{without_member.get('access-control-max-age')!r}"
    )

    served = _await_grant(ctx, s3.generate_presigned_url(
        "get_object", Params={"Bucket": timed, "Key": _OBJECT_KEY}, ExpiresIn=600))
    assert served["body"] == _OBJECT_BODY, (
        f"the actual GET served {served['body']!r}, expected {_OBJECT_BODY!r}"
    )
    # S3 answers the rule's Max-Age on an actual request as well, not only on the preflight.
    assert served["headers"].get("access-control-max-age") == str(_CACHE_FOR_S), (
        "the actual GET under the rule carrying MaxAgeSeconds answered Access-Control-Max-Age "
        f"{served['headers'].get('access-control-max-age')!r}, expected {str(_CACHE_FOR_S)!r}"
    )


def _unsigned_url(ctx, bucket: str, key: str) -> str:
    """The object URL a page's script preflights, with no signature on it."""
    aws_form = f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{urllib.parse.quote(key)}"
    return ctx.s3_object_url(aws_form, bucket, key)


def _budget(ctx, budget_s: float) -> float:
    """``budget_s``, trimmed so the check fails with its own message before the runner stops it."""
    remaining = ctx.time_left()
    return budget_s if remaining is None else min(budget_s, remaining / 4)


def _await_preflight(ctx, url: str, budget_s: float = 40.0) -> dict:
    """The preflight's lower-cased headers once it is a 200; raises when the budget is spent."""
    give_up_at = time.monotonic() + _budget(ctx, budget_s)
    asking = {"Origin": _SITE, "Access-Control-Request-Method": "GET"}
    while True:
        answer = requests.options(url, headers=asking, timeout=60, verify=ctx.http_verify,
                                  allow_redirects=True)
        if answer.status_code == 200:
            return {name.lower(): value for name, value in answer.headers.items()}
        if time.monotonic() > give_up_at:
            raise AssertionError(
                f"the preflight was still answering {answer.status_code!r}, never 200: "
                f"{answer.content[:300]!r}"
            )
        time.sleep(2)


def _await_grant(ctx, url: str, budget_s: float = 40.0) -> dict:
    """The GET's {headers, body} once Allow-Origin names the site; raises when time is up."""
    give_up_at = time.monotonic() + _budget(ctx, budget_s)
    while True:
        answer = requests.get(url, headers={"Origin": _SITE}, timeout=60,
                              verify=ctx.http_verify, allow_redirects=True)
        headers = {name.lower(): value for name, value in answer.headers.items()}
        if headers.get("access-control-allow-origin") == _SITE:
            return {"headers": headers, "body": answer.content}
        if time.monotonic() > give_up_at:
            raise AssertionError(
                f"the GET answered {answer.status_code!r} with Allow-Origin "
                f"{headers.get('access-control-allow-origin')!r}, expected {_SITE!r}"
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
    name = ctx.unique_name("sim2real-behav-age-")
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
