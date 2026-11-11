"""bucket-policy-status-reflects-policy."""
from __future__ import annotations

import json
import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-policy-status-reflects-policy"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBucketPolicyStatus fails with NoSuchBucketPolicy before any policy, reports IsPublic=true for a
    Principal "*" grant conditioned only on a secret Referer, and keeps IsPublic=true after Block Public
    Access is re-enabled: the status describes the policy document."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-polstat-")
    _create_bucket(ctx, s3, name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))

    # With no bucket policy attached yet, GetBucketPolicyStatus itself errors out
    # on real S3 (there is no policy to compute a status for).
    initial_code, initial_message = _error(lambda: s3.get_bucket_policy_status(Bucket=name))
    assert initial_code == "NoSuchBucketPolicy", (
        f"expected NoSuchBucketPolicy for a bucket with no policy attached, got {initial_code!r}"
    )
    assert initial_message == "The bucket policy does not exist", initial_message

    # Lift only BlockPublicPolicy and RestrictPublicBuckets so the policy below can be attached.
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )

    # S3 counts a grant conditioned on aws:Referer as public, and the per-run secret keeps the
    # grant usable by nobody else.
    referer = secrets.token_urlsafe(32)

    public_policy = {
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
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(public_policy))

    status = s3.get_bucket_policy_status(Bucket=name)
    assert status["PolicyStatus"]["IsPublic"] is True, (
        f"expected IsPublic=True after attaching a Principal:* GetObject policy, got {status['PolicyStatus']!r}"
    )

    # Restrict public access again -- this changes whether the public grant
    # in the policy can actually be exercised, but it does not rewrite the
    # policy document, so the policy-status computation is unchanged: it must
    # keep reporting IsPublic=true.
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    # Give any (unexpected) asynchronous re-evaluation a moment, but the
    # expected outcome is that the status is stable and remains public.
    status2 = _poll_until(
        lambda: s3.get_bucket_policy_status(Bucket=name),
        lambda resp: resp["PolicyStatus"]["IsPublic"] is True,
    )
    assert status2["PolicyStatus"]["IsPublic"] is True, (
        "expected IsPublic to remain True after re-enabling the public access block "
        f"(status reflects the policy document, not current enforcement), got {status2['PolicyStatus']!r}"
    )


def _poll_until(fn, predicate, attempts: int = 10, delay: float = 1.0):
    """Call fn() repeatedly until predicate(result) is truthy or attempts run out."""
    import time

    last = None
    for _ in range(attempts):
        last = fn()
        if predicate(last):
            return last
        time.sleep(delay)
    return last


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str, bypass_governance: bool = False) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            to_delete = []
            for v in page.get("Versions", []):
                to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for m in page.get("DeleteMarkers", []):
                to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
            if to_delete:
                kwargs = {"Bucket": name, "Delete": {"Objects": to_delete}}
                if bypass_governance:
                    kwargs["BypassGovernanceRetention"] = True
                failed = s3.delete_objects(**kwargs).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    # Public access block / policy must be cleared before delete in some configs.
    try:
        s3.delete_bucket_policy(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_public_access_block(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
