"""requester-pays-enforcement."""

from __future__ import annotations
import itertools
import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "requester-pays-enforcement"
GROUP = 'auth_enforcement'
SERVICES = ['s3']

_ANON_PROBES = itertools.count()


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


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _err_or_result(fn):
    """Call fn(); return its ClientError (Error.Code, Error.Message), else fn()'s own result."""
    try:
        return fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")
        time.sleep(interval_s)


def _anon_client(ctx, referer):
    """An S3 client from ctx that sends NO SigV4 signature (botocore UNSIGNED) and `referer`.

    Each call returns a distinct client (and so a fresh connection pool): a distinct
    user_agent_extra gives ctx.client a distinct cache key.
    """
    from botocore import UNSIGNED
    from botocore.config import Config

    # Standard mode retries transient 5xx/SlowDown but not AccessDenied; the RequestPayment
    # propagation delay is handled by _poll_until in run().
    cfg = Config(
        signature_version=UNSIGNED,
        retries={"max_attempts": 5, "mode": "standard"},
        user_agent_extra=f"anon-probe/{next(_ANON_PROBES)}",
    )
    anon = ctx.client("s3", config=cfg)

    def _add_referer(request, **_):
        request.headers["Referer"] = referer

    anon.meta.events.register("before-sign.s3", _add_referer)
    return anon


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With Payer=Requester, an unsigned GetObject without x-amz-request-payer fails with
    AccessDenied and S3's exact anonymous-requester message; after Payer is reset to BucketOwner
    the same call (allowed by a secret-Referer grant) returns the object's bytes."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "payer.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"large-shared-dataset")

    # Allow just enough public access that the anonymous probe is blocked by Requester Pays alone:
    # only requests carrying this per-run secret as Referer may read the object.
    referer = secrets.token_urlsafe(32)
    s3.put_public_access_block(
        Bucket=bucket,
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
                "Sid": "PublicReadForRequesterPaysProbe",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{key}",
                "Condition": {"StringEquals": {"aws:Referer": referer}},
            }
        ],
    }
    try:
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("AccessDenied", "AccessDeniedByBlockPublicPolicy"):
            raise AssertionError(
                "account-level Block Public Access forbids the bucket policy this check requires"
            )
        raise

    try:
        s3.put_bucket_request_payment(Bucket=bucket, RequestPaymentConfiguration={"Payer": "Requester"})
        payer = s3.get_bucket_request_payment(Bucket=bucket)["Payer"]
        assert payer == "Requester", f"expected Payer=Requester after PutBucketRequestPayment, got {payer}"

        # Enforcement is eventually consistent, and a kept-alive connection can see a stale
        # RequestPayment value for tens of seconds, so each attempt uses a fresh anonymous client.
        refusal = _poll_until(
            lambda: _err_or_result(lambda: _anon_client(ctx, referer).get_object(Bucket=bucket, Key=key)),
            lambda r: isinstance(r, tuple) and r[0] == "AccessDenied",
            timeout_s=30.0,
            description="anonymous GetObject denied for a Requester-Pays bucket without a RequestPayer ack",
        )
        assert refusal == (
            "AccessDenied",
            "Anonymous users cannot invoke requests against Requester Pays buckets. "
            "Please authenticate.",
        ), (
            f"expected AccessDenied for GetObject without RequestPayer ack, got {refusal!r}"
        )

        # Same unsigned client and policy, only RequestPayment changes: isolates it as the cause.
        s3.put_bucket_request_payment(Bucket=bucket, RequestPaymentConfiguration={"Payer": "BucketOwner"})
        resp = _poll_until(
            lambda: _err_or_result(lambda: _anon_client(ctx, referer).get_object(Bucket=bucket, Key=key)),
            lambda r: not isinstance(r, tuple),
            timeout_s=30.0,
            description="anonymous GetObject succeeding again after RequestPayment reset to BucketOwner",
        )
        body = resp["Body"].read()
        assert body == b"large-shared-dataset", f"expected the object body back, got {body!r}"
    finally:
        s3.delete_bucket_policy(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
