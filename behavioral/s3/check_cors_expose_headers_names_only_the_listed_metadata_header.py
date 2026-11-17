"""cors-expose-headers-names-only-the-listed-metadata-header."""
from __future__ import annotations

import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-expose-headers-names-only-the-listed-metadata-header"
GROUP = "cors"
SERVICES = ["s3"]

_SITE = "https://reader.example.org"
_OBJECT_KEY = "metadata/annotated.txt"
_OBJECT_BODY = b"two metadata headers, one of them exposed"
_LISTED_META = "x-amz-meta-edition"
_UNLISTED_META = "x-amz-meta-shelf"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """Access-Control-Expose-Headers on a presigned GET names only the metadata header the rule's
    ExposeHeaders lists, while the unlisted one is still sent with the object.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors-troubleshooting.html
    """
    s3 = ctx.client("s3")
    bucket = _make_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_OBJECT_KEY, Body=_OBJECT_BODY, ContentType="text/plain",
                  Metadata={"edition": "first", "shelf": "upper"})
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_SITE],
        "AllowedMethods": ["GET"],
        "AllowedHeaders": ["content-type"],
        "ExposeHeaders": [_LISTED_META],
    }]})

    signed_read = s3.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": _OBJECT_KEY}, ExpiresIn=600
    )
    served = _await_cors_grant(ctx, signed_read)
    assert served["body"] == _OBJECT_BODY, (
        f"the GET served {served['body']!r}, expected {_OBJECT_BODY!r}"
    )
    assert served["headers"].get("access-control-expose-headers") == _LISTED_META, (
        "Access-Control-Expose-Headers was "
        f"{served['headers'].get('access-control-expose-headers')!r}, expected {_LISTED_META!r}"
    )
    assert served["headers"].get(_LISTED_META) == "first", (
        f"the listed metadata header was {served['headers'].get(_LISTED_META)!r}, expected 'first'"
    )
    # The rule governs what a browser may read, not what S3 sends: the unlisted header is there.
    assert served["headers"].get(_UNLISTED_META) == "upper", (
        f"the unlisted metadata header was {served['headers'].get(_UNLISTED_META)!r}, "
        "expected 'upper' to be sent with the object anyway"
    )

    stored = s3.head_object(Bucket=bucket, Key=_OBJECT_KEY)
    assert stored["Metadata"] == {"edition": "first", "shelf": "upper"}, (
        f"HeadObject reports the metadata as {stored['Metadata']!r}, expected both entries"
    )


def _send(ctx, url: str) -> dict:
    """{status, headers, body} of one GET carrying the Origin; a 4xx answer is returned."""
    answer = requests.get(url, headers={"Origin": _SITE}, timeout=60,
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
                f"after {budget_s:.0f}s the GET answered {answer['status']!r} with Allow-Origin "
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
    name = ctx.unique_name("sim2real-behav-expose-")
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
