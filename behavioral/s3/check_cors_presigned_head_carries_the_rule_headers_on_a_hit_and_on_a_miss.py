"""cors-presigned-head-carries-the-rule-headers-on-a-hit-and-on-a-miss."""
from __future__ import annotations

import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-presigned-head-carries-the-rule-headers-on-a-hit-and-on-a-miss"
GROUP = "cors"
SERVICES = ["s3"]

_SITE = "https://viewer.example.net"
_STORED_KEY = "thumbnails/stored.bin"
_ABSENT_KEY = "thumbnails/never-written.bin"
_OBJECT_BODY = b"0123456789abcdef"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A presigned HEAD carrying an allowed Origin answers the rule's CORS headers both for a
    stored key and for a key that does not exist, where the bodiless 404 carries no other evidence.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html
    """
    s3 = ctx.client("s3")
    bucket = _make_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_STORED_KEY, Body=_OBJECT_BODY,
                  ContentType="application/octet-stream")
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_SITE],
        "AllowedMethods": ["HEAD"],
        "AllowedHeaders": ["content-type"],
    }]})

    hit = _await_cors_grant(ctx, _signed_head(s3, bucket, _STORED_KEY))
    assert hit["status"] == 200, (
        f"the HEAD of the stored key answered {hit['status']!r}, expected 200"
    )
    assert hit["headers"].get("access-control-allow-methods") == "HEAD", (
        "the HEAD of the stored key answered Access-Control-Allow-Methods "
        f"{hit['headers'].get('access-control-allow-methods')!r}, expected 'HEAD'"
    )
    assert hit["headers"].get("content-length") == str(len(_OBJECT_BODY)), (
        f"the HEAD of the stored key reported Content-Length "
        f"{hit['headers'].get('content-length')!r}, expected {len(_OBJECT_BODY)!r}"
    )
    assert hit["body"] == b"", f"the HEAD of the stored key returned a body: {hit['body'][:300]!r}"

    miss = _send(ctx, _signed_head(s3, bucket, _ABSENT_KEY))
    assert miss["status"] == 404, (
        f"the HEAD of the absent key answered {miss['status']!r}, expected 404"
    )
    assert miss["body"] == b"", (
        f"the HEAD of the absent key returned a body: {miss['body'][:300]!r}"
    )
    assert miss["headers"].get("access-control-allow-origin") == _SITE, (
        "the HEAD of the absent key answered Access-Control-Allow-Origin "
        f"{miss['headers'].get('access-control-allow-origin')!r}, expected {_SITE!r}"
    )
    assert miss["headers"].get("access-control-allow-methods") == "HEAD", (
        "the HEAD of the absent key answered Access-Control-Allow-Methods "
        f"{miss['headers'].get('access-control-allow-methods')!r}, expected 'HEAD'"
    )
    assert "origin" in (miss["headers"].get("vary") or "").lower(), (
        f"the HEAD of the absent key answered Vary {miss['headers'].get('vary')!r}, "
        "which must name Origin"
    )


def _signed_head(s3, bucket: str, key: str) -> str:
    """A presigned HeadObject URL a page's script can send without credentials."""
    return s3.generate_presigned_url(
        "head_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=600
    )


def _send(ctx, url: str) -> dict:
    """{status, headers, body} of one HEAD carrying the Origin; a 4xx answer is returned."""
    answer = requests.head(url, headers={"Origin": _SITE}, timeout=60,
                           verify=ctx.http_verify, allow_redirects=True)
    return {"status": answer.status_code,
            "headers": {n.lower(): v for n, v in answer.headers.items()},
            "body": answer.content}


def _await_cors_grant(ctx, url: str, budget_s: float = 40.0) -> dict:
    """The answer once Allow-Origin names the site; raises with the last one when time is up."""
    remaining = ctx.time_left()
    if remaining is not None:
        # Keep room for the check's own failure message instead of the runner's timeout.
        budget_s = min(budget_s, remaining / 3)
    give_up_at = time.monotonic() + budget_s
    while True:
        answer = _send(ctx, url)
        if answer["headers"].get("access-control-allow-origin") == _SITE:
            return answer
        if time.monotonic() > give_up_at:
            raise AssertionError(
                f"after {budget_s:.0f}s the HEAD answered {answer['status']!r} with Allow-Origin "
                f"{answer['headers'].get('access-control-allow-origin')!r}, expected {_SITE!r}"
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
    name = ctx.unique_name("sim2real-behav-head-")
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
