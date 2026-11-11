"""account-public-access-block-blocks-public-bucket-policy-rejected."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-public-access-block-blocks-public-bucket-policy-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:s3-account-public-access-block")
def run(ctx) -> None:
    """A public bucket policy is accepted without an account block and rejected once one exists.

    The bucket's own block never blocks policies; the rejection leaves the bucket policy-less,
    a scoped policy is still accepted, and deleting the account block lifts the restriction.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    bucket = ctx.unique_name("sim2real-behav-pabpol-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    # The bucket's own block allows public policies; its ACL blocks stay on.
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        },
    )

    # S3 classifies a grant to "*" conditioned on aws:Referer as public; the per-run secret keeps
    # the grant unusable by anyone else.
    public = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"aws:Referer": secrets.token_urlsafe(32)}},
            }
        ],
    })

    # Without an account-level block the very same document is accepted.
    s3.put_bucket_policy(Bucket=bucket, Policy=public)
    assert s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"] is True, (
        "the baseline public policy was not recognised as public"
    )
    s3.delete_bucket_policy(Bucket=bucket)

    all_on = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    # The account-level block is a one-per-account record: snapshot it and restore exactly that.
    # Registered before the write, not after: _ensure_account_pab retries, so an abort inside
    # it must still leave a restore behind for the Put that did land.
    original_pab = _read_account_pab(s3c, account)
    ctx.on_cleanup(lambda: _restore_account_pab(s3c, account, original_pab))
    echoed = _ensure_account_pab(s3c, account, all_on)
    assert echoed["BlockPublicPolicy"] is True, (
        f"GetPublicAccessBlock reported {echoed!r} after enabling all four flags"
    )

    code, code_msg = _error(lambda: s3.put_bucket_policy(Bucket=bucket, Policy=public))
    assert code == "AccessDenied", (
        f"the same public bucket policy under an account-level BlockPublicPolicy returned "
        f"{code!r}, expected AccessDenied"
    )
    code_want = f"User: {caller} is not authorized to perform: s3:PutBucketPolicy on resource: \"arn:aws:s3:::{bucket}\" because public policies are prevented by the BlockPublicPolicy setting in S3 Block Public Access."
    assert code_msg == code_want, (
        f"the refusal carried message {code_msg!r}, expected {code_want!r}"
    )
    absent, absent_msg = _error(lambda: s3.get_bucket_policy(Bucket=bucket))
    assert absent == "NoSuchBucketPolicy", (
        f"the rejected PutBucketPolicy left a policy behind: GetBucketPolicy returned "
        f"{absent!r}, expected NoSuchBucketPolicy"
    )
    absent_want = "The bucket policy does not exist"
    assert absent_msg == absent_want, (
        f"the refusal carried message {absent_msg!r}, expected {absent_want!r}"
    )

    # Positive control: the block is evaluated against the DOCUMENT, not the operation.
    scoped = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ScopedRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    })
    s3.put_bucket_policy(Bucket=bucket, Policy=scoped)
    ctx.on_cleanup(lambda: _drop_bucket_policy(s3, bucket))
    assert s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"] is False, (
        "the scoped control policy was classified as public"
    )

    # DeletePublicAccessBlock lifts the restriction: the same public document becomes
    # acceptable again. Asserted through the EFFECT rather than through a GetPublicAccessBlock
    # 404, because that metadata read is not reliably observable — see the note in
    # _poll_public_policy_accepted.
    s3.delete_bucket_policy(Bucket=bucket)
    s3c.delete_public_access_block(AccountId=account)
    assert _poll_public_policy_accepted(s3, bucket, public), (
        "after DeletePublicAccessBlock the same public bucket policy was still rejected; the "
        "account-level block behaved as a sticky flag rather than a live evaluation"
    )
    assert s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"] is True, (
        "the policy accepted after the block was removed is not classified as public"
    )


# ===== helpers =====

def _ensure_account_pab(s3c, account: str, config: dict, attempts: int = 25) -> dict:
    """Put the account-level PublicAccessBlock and wait until GET actually serves it.

    Writes to this record are eventually consistent and not linearizable: an earlier delete can
    land ~40s later and clobber this Put, so the Put is re-issued on divergence.
    """
    served = None
    for _ in range(attempts):
        s3c.put_public_access_block(AccountId=account, PublicAccessBlockConfiguration=config)
        time.sleep(2)
        try:
            served = s3c.get_public_access_block(AccountId=account)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
            served = exc.response["Error"]["Code"]
            continue
        if served == config:
            return served
    raise AssertionError(
        f"the account-level PublicAccessBlock never converged on {config!r}; "
        f"the last read served {served!r}"
    )

def _poll_public_policy_accepted(s3, bucket: str, policy: str, attempts: int = 45) -> bool:
    """Retry PutBucketPolicy until the public document is accepted; True if it ever was.

    DeletePublicAccessBlock's GetPublicAccessBlock 404 can lag by more than 90s, but the block's
    effect lifts much sooner, so retrying on AccessDenied is the usable wait.
    """
    for _ in range(attempts):
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=policy)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
        time.sleep(2)
    return False


def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``; raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _read_account_pab(s3c, account: str) -> dict | None:
    """The account-level PublicAccessBlock as it stands, or None when none is configured."""
    try:
        return s3c.get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        return None


def _restore_account_pab(s3c, account: str, original: dict | None) -> None:
    """Put back exactly the account-level block that existed before the check ran, re-issuing the
    write every 2 s until GetPublicAccessBlock serves it; raise if it never does within the deadline.

    An earlier write can land late and clobber the restore, as in _ensure_account_pab."""

    def _write() -> None:
        if original is None:
            try:
                s3c.delete_public_access_block(AccountId=account)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                    raise
        else:
            s3c.put_public_access_block(AccountId=account, PublicAccessBlockConfiguration=original)

    # Writes to this record are eventually consistent; 300 s stays inside the cleanup budget.
    deadline = time.monotonic() + 300.0
    _write()
    served = _read_account_pab(s3c, account)
    while served != original:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the account-level PublicAccessBlock was not restored to {original!r}; "
                f"GetPublicAccessBlock still serves {served!r}"
            )
        time.sleep(2)
        served = _read_account_pab(s3c, account)
        if served != original:
            _write()
            time.sleep(2)
            served = _read_account_pab(s3c, account)


def _drop_bucket_policy(s3, bucket: str) -> None:
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchBucketPolicy"):
            raise


def _create_bucket(ctx, s3, name: str) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
