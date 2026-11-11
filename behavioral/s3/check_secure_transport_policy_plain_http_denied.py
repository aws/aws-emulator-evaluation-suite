"""secure-transport-policy-plain-http-denied."""
from __future__ import annotations

import json
import time
from urllib.parse import urlsplit, urlunsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secure-transport-policy-plain-http-denied"
GROUP = "bucket-policy"
SERVICES = ["s3"]


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Deny-unless-aws:SecureTransport bucket policy makes signed plain-HTTP Get, Put and List
    AccessDenied while HTTPS keeps working; plain HTTP works before the policy and after deletion.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html
    """
    s3 = ctx.client("s3")
    http_s3 = ctx.client("s3", endpoint_url=_with_scheme(s3.meta.endpoint_url, "http"))
    assert urlsplit(http_s3.meta.endpoint_url).scheme == "http", http_s3.meta.endpoint_url

    bucket = ctx.unique_name("sim2real-behav-tls-")
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="a.txt", Body=b"alpha")

    # Baseline: plain HTTP is served when no policy forbids it.
    base = http_s3.get_object(Bucket=bucket, Key="a.txt")["Body"].read()
    assert base == b"alpha", f"plain-HTTP GetObject with no policy returned {base!r}"

    arn = f"arn:aws:s3:::{bucket}"
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": [arn, f"{arn}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }],
    }))
    ctx.on_cleanup(lambda: s3.delete_bucket_policy(Bucket=bucket))

    _settle(lambda: _error_code(lambda: http_s3.get_object(Bucket=bucket, Key="a.txt")),
            "AccessDenied", description="plain-HTTP GetObject under the policy")
    # The AccessDenied message names the caller's own ARN, so it is read from STS, not pinned.
    put_code, put_message = _error(lambda: http_s3.put_object(Bucket=bucket, Key="b.txt", Body=b"beta"))
    assert put_code == "AccessDenied", f"plain-HTTP PutObject should be exactly AccessDenied, got {put_code!r}"
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        f'User: {caller_arn} is not authorized to perform: s3:PutObject on resource: '
        f'"{arn}/b.txt" with an explicit deny in a resource-based policy'
    )
    assert put_message == expected, f"expected message {expected!r}, got {put_message!r}"
    list_code = _error_code(lambda: http_s3.list_objects_v2(Bucket=bucket))
    assert list_code == "AccessDenied", (
        f"plain-HTTP ListObjectsV2 (bucket-ARN resource) should be exactly AccessDenied, got {list_code!r}"
    )
    absent = _error_code(lambda: s3.head_object(Bucket=bucket, Key="b.txt"))
    assert absent == "404", f"the refused plain-HTTP PutObject created b.txt anyway: {absent!r}"

    # Positive control under the same policy: HTTPS is untouched.
    tls = s3.get_object(Bucket=bucket, Key="a.txt")["Body"].read()
    assert tls == b"alpha", f"HTTPS GetObject under the policy returned {tls!r}"
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
    assert keys == ["a.txt"], f"HTTPS listing under the policy returned {keys!r}"

    # Repair: remove the policy and the very request that was refused now succeeds over HTTP.
    s3.delete_bucket_policy(Bucket=bucket)
    _settle(lambda: _error_code(lambda: http_s3.get_object(Bucket=bucket, Key="a.txt")),
            "UNEXPECTED_SUCCESS", description="plain-HTTP GetObject after deleting the policy",
            # A deleted Deny usually stops applying in ~4 s but can stay enforced past 90 s.
            timeout_s=420)
    http_s3.put_object(Bucket=bucket, Key="b.txt", Body=b"beta")
    landed = s3.get_object(Bucket=bucket, Key="b.txt")["Body"].read()
    assert landed == b"beta", f"plain-HTTP PutObject after repair stored {landed!r}"


def _error_code(fn):
    """The exact AWS error code, or a sentinel no code can equal when the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _error(fn):
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _settle(probe, want, *, description, streak=3, timeout_s=300, interval_s=2):
    """Poll until probe() returns `want` on `streak` consecutive calls (policy propagation)."""
    deadline = time.monotonic() + timeout_s
    seen, run = [], 0
    while True:
        got = probe()
        seen.append(got)
        run = run + 1 if got == want else 0
        if run >= streak:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: wanted {want!r} {streak}x in a row within {timeout_s}s; "
                f"last observations {seen[-10:]!r}"
            )
        time.sleep(interval_s)


def _with_scheme(url, scheme):
    parts = urlsplit(url)
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, parts.fragment))


def _delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for o in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=o["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
