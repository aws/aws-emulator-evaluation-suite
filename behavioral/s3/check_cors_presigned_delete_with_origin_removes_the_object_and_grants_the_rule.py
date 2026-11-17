"""cors-presigned-delete-with-origin-removes-the-object-and-grants-the-rule."""
from __future__ import annotations

import time
import urllib.parse

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-presigned-delete-with-origin-removes-the-object-and-grants-the-rule"
GROUP = "cors"
SERVICES = ["s3"]

_SITE = "https://console.example.com"
_OBJECT_KEY = "drafts/discarded.txt"
_OBJECT_BODY = b"a draft a page's script throws away"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A presigned DELETE sent with an Origin a DELETE rule allows answers 204 with that rule's
    CORS headers, and the object it addressed is gone from the bucket afterwards.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html
    """
    s3 = ctx.client("s3")
    bucket = _make_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_OBJECT_KEY, Body=_OBJECT_BODY, ContentType="text/plain")
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
        "AllowedOrigins": [_SITE],
        "AllowedMethods": ["DELETE"],
        "AllowedHeaders": ["content-type"],
    }]})

    # The preflight is the one way to see the rule is live without spending the delete on it.
    cleared = _await_preflight(ctx, _unsigned_url(ctx, bucket, _OBJECT_KEY))
    assert cleared["headers"].get("access-control-allow-methods") == "DELETE", (
        "the preflight answered Access-Control-Allow-Methods "
        f"{cleared['headers'].get('access-control-allow-methods')!r}, expected 'DELETE'"
    )

    signed_delete = s3.generate_presigned_url(
        "delete_object", Params={"Bucket": bucket, "Key": _OBJECT_KEY}, ExpiresIn=600
    )
    removed = requests.delete(signed_delete, headers={"Origin": _SITE}, timeout=60,
                              verify=ctx.http_verify, allow_redirects=True)
    answered = {name.lower(): value for name, value in removed.headers.items()}
    assert removed.status_code == 204, (
        f"the presigned DELETE answered {removed.status_code!r}, expected 204: "
        f"{removed.content[:300]!r}"
    )
    assert answered.get("access-control-allow-origin") == _SITE, (
        "the presigned DELETE answered Access-Control-Allow-Origin "
        f"{answered.get('access-control-allow-origin')!r}, expected {_SITE!r}"
    )
    assert answered.get("access-control-allow-methods") == "DELETE", (
        "the presigned DELETE answered Access-Control-Allow-Methods "
        f"{answered.get('access-control-allow-methods')!r}, expected 'DELETE'"
    )
    assert removed.content == b"", (
        f"the presigned DELETE returned a body: {removed.content[:300]!r}"
    )

    refusal = _refused(lambda: s3.get_object(Bucket=bucket, Key=_OBJECT_KEY))
    assert refusal == ("NoSuchKey", "The specified key does not exist."), (
        f"reading the deleted key answered {refusal!r}, so the browser's DELETE kept it"
    )
    remaining = {stored["Key"]
                 for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
                 for stored in page.get("Contents", [])}
    assert _OBJECT_KEY not in remaining, (
        f"the deleted key is still listed among this bucket's {len(remaining)} object(s)"
    )


def _refused(call) -> tuple:
    """(code, message) of the ClientError ``call`` raises; a success raises instead."""
    try:
        call()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the read of the deleted key succeeded, where a refusal was expected")


def _unsigned_url(ctx, bucket: str, key: str) -> str:
    """The object URL a page's script preflights, with no signature on it."""
    aws_form = f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{urllib.parse.quote(key)}"
    return ctx.s3_object_url(aws_form, bucket, key)


def _await_preflight(ctx, url: str, budget_s: float = 40.0) -> dict:
    """The DELETE preflight answer once it is a 200; raises with the last one when time is up."""
    remaining = ctx.time_left()
    if remaining is not None:
        # Keep room for the check's own failure message instead of the runner's timeout.
        budget_s = min(budget_s, remaining / 3)
    give_up_at = time.monotonic() + budget_s
    asking = {"Origin": _SITE, "Access-Control-Request-Method": "DELETE"}
    while True:
        answer = requests.options(url, headers=asking, timeout=60, verify=ctx.http_verify,
                                  allow_redirects=True)
        if answer.status_code == 200:
            return {"status": answer.status_code,
                    "headers": {n.lower(): v for n, v in answer.headers.items()}}
        if time.monotonic() > give_up_at:
            raise AssertionError(
                f"the DELETE preflight was still answering {answer.status_code!r} after "
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
    name = ctx.unique_name("sim2real-behav-del-")
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
