"""cors-presigned-get-from-the-allowed-origin-without-its-port-rejected."""
from __future__ import annotations

import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-presigned-get-from-the-allowed-origin-without-its-port-rejected"
GROUP = "cors"
SERVICES = ["s3"]

_LISTED = "http://www.example.com:8080"
_SAME_HOST_NO_PORT = "http://www.example.com"
_OBJECT_KEY = "ported/banner.txt"
_OBJECT_BODY = b"served to a page on a non-default port"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """An origin matches AllowedOrigins only with its port: a presigned GET from the same host
    without the listed port is served with no CORS headers, with the port it carries the rule's.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors-troubleshooting.html
    """
    s3 = ctx.client("s3")
    bucket = _make_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_OBJECT_KEY, Body=_OBJECT_BODY, ContentType="text/plain")
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_LISTED],
        "AllowedMethods": ["GET"],
        "AllowedHeaders": ["content-type"],
    }]})

    signed_read = s3.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": _OBJECT_KEY}, ExpiresIn=600
    )

    # The exact origin is the legal neighbour of the port-less one, and proves the rule is live.
    allowed = _await_cors_grant(ctx, signed_read, _LISTED)
    assert allowed["body"] == _OBJECT_BODY, (
        f"the GET from the listed origin served {allowed['body']!r}, expected {_OBJECT_BODY!r}"
    )
    assert allowed["headers"].get("access-control-allow-methods") == "GET", (
        "the GET from the listed origin answered Access-Control-Allow-Methods "
        f"{allowed['headers'].get('access-control-allow-methods')!r}, expected 'GET'"
    )

    unported = _send(ctx, signed_read, _SAME_HOST_NO_PORT)
    assert unported["status"] == 200, (
        f"the GET from the port-less origin answered {unported['status']!r}, expected 200: "
        f"{unported['body'][:300]!r}"
    )
    assert unported["body"] == _OBJECT_BODY, (
        f"the GET from the port-less origin served {unported['body']!r}, expected {_OBJECT_BODY!r}"
    )
    granted = {name: value for name, value in unported["headers"].items()
               if name.startswith("access-control-")}
    assert granted == {}, (
        f"the port-less origin was granted {granted!r}, expected no Access-Control-* header"
    )
    assert "vary" not in unported["headers"], (
        f"the port-less origin's answer carried Vary {unported['headers'].get('vary')!r}"
    )


def _send(ctx, url: str, origin: str) -> dict:
    """{status, headers, body} of one GET carrying a browser Origin; a 4xx answer is returned."""
    answer = requests.get(url, headers={"Origin": origin}, timeout=60,
                          verify=ctx.http_verify, allow_redirects=True)
    return {"status": answer.status_code,
            "headers": {n.lower(): v for n, v in answer.headers.items()},
            "body": answer.content}


def _await_cors_grant(ctx, url: str, origin: str, budget_s: float = 40.0) -> dict:
    """The answer once Allow-Origin names ``origin``; raises with the last one when time is up."""
    remaining = ctx.time_left()
    if remaining is not None:
        # Keep room for the check's own failure message instead of the runner's timeout.
        budget_s = min(budget_s, remaining / 3)
    give_up_at = time.monotonic() + budget_s
    while True:
        answer = _send(ctx, url, origin)
        if answer["headers"].get("access-control-allow-origin") == origin:
            return answer
        if time.monotonic() > give_up_at:
            raise AssertionError(
                f"after {budget_s:.0f}s the listed origin's GET answered {answer['status']!r} with "
                f"Allow-Origin {answer['headers'].get('access-control-allow-origin')!r}, "
                f"expected {origin!r}"
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
    name = ctx.unique_name("sim2real-behav-port-")
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
