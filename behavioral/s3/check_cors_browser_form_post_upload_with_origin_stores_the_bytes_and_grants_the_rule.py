"""cors-browser-form-post-upload-with-origin-stores-the-bytes-and-grants-the-rule."""
from __future__ import annotations

import time
import urllib.parse

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-browser-form-post-upload-with-origin-stores-the-bytes-and-grants-the-rule"
GROUP = "cors"
SERVICES = ["s3"]

_SITE = "https://uploader.example.com"
_OBJECT_KEY = "inbox/from-a-form.txt"
_OBJECT_BODY = b"bytes a browser form posted straight to S3"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A browser form POST to a presigned policy, sent with an Origin a POST rule allows, stores
    the bytes and answers that rule's CORS headers, which is all a page's script can read.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html
    """
    s3 = ctx.client("s3")
    bucket = _make_bucket(ctx, s3)
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_SITE],
        "AllowedMethods": ["POST"],
        "AllowedHeaders": ["content-type"],
    }]})

    # The preflight shows the rule is in effect before the one upload is spent on it.
    cleared = _await_preflight(ctx, _unsigned_url(ctx, bucket, _OBJECT_KEY))
    assert cleared.get("access-control-allow-methods") == "POST", (
        "the form preflight answered Access-Control-Allow-Methods "
        f"{cleared.get('access-control-allow-methods')!r}, expected 'POST'"
    )

    form = s3.generate_presigned_post(Bucket=bucket, Key=_OBJECT_KEY, ExpiresIn=600)
    uploaded = requests.post(form["url"], data=form["fields"],
                             files={"file": ("from-a-form.txt", _OBJECT_BODY)},
                             headers={"Origin": _SITE}, timeout=60, verify=ctx.http_verify,
                             allow_redirects=True)
    answered = {name.lower(): value for name, value in uploaded.headers.items()}
    assert uploaded.status_code == 204, (
        f"the form POST answered {uploaded.status_code!r}, expected 204: "
        f"{uploaded.content[:300]!r}"
    )
    assert answered.get("access-control-allow-origin") == _SITE, (
        "the form POST answered Access-Control-Allow-Origin "
        f"{answered.get('access-control-allow-origin')!r}, expected {_SITE!r}"
    )
    assert answered.get("access-control-allow-methods") == "POST", (
        "the form POST answered Access-Control-Allow-Methods "
        f"{answered.get('access-control-allow-methods')!r}, expected 'POST'"
    )

    stored = s3.get_object(Bucket=bucket, Key=_OBJECT_KEY)
    body = stored["Body"].read()
    assert body == _OBJECT_BODY, (
        f"the object the form uploaded holds {body!r}, expected {_OBJECT_BODY!r}"
    )
    keys = {entry["Key"]
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
            for entry in page.get("Contents", [])}
    assert keys == {_OBJECT_KEY}, (
        f"the form POST left this bucket holding {sorted(keys)!r}, expected only the signed key"
    )


def _unsigned_url(ctx, bucket: str, key: str) -> str:
    """The object URL a page's form preflights, with no signature on it."""
    aws_form = f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{urllib.parse.quote(key)}"
    return ctx.s3_object_url(aws_form, bucket, key)


def _await_preflight(ctx, url: str, budget_s: float = 40.0) -> dict:
    """The POST preflight's lower-cased headers once it is a 200; raises when time is up."""
    remaining = ctx.time_left()
    if remaining is not None:
        # Keep room for the check's own failure message instead of the runner's timeout.
        budget_s = min(budget_s, remaining / 3)
    give_up_at = time.monotonic() + budget_s
    asking = {"Origin": _SITE, "Access-Control-Request-Method": "POST"}
    while True:
        answer = requests.options(url, headers=asking, timeout=60, verify=ctx.http_verify,
                                  allow_redirects=True)
        if answer.status_code == 200:
            return {name.lower(): value for name, value in answer.headers.items()}
        if time.monotonic() > give_up_at:
            raise AssertionError(
                f"the form preflight was still answering {answer.status_code!r} after "
                f"{budget_s:.0f}s, never 200: {answer.content[:300]!r}"
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
    name = ctx.unique_name("sim2real-behav-form-")
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
