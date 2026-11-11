"""account-public-access-block-blocks-public-access-point-policy-rejected."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-public-access-block-blocks-public-access-point-policy-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:s3-account-public-access-block")
def run(ctx) -> None:
    """The account block rejects a public access point policy with bucket and AP policy blocks off;
    once DeletePublicAccessBlock removes it the identical policy is accepted and reports
    IsPublic=true, so the rejection was a live evaluation, not a sticky flag."""
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-pabap-")
    name = ctx.unique_name("sim2real-behav-pabap-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
    })

    ap_arn = s3c.create_access_point(
        AccountId=account, Name=name, Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
        Tags=[{"Key": "sim2real", "Value": "pabap"}],
    )["AccessPointArn"]
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, name))
    own = s3c.get_access_point(AccountId=account, Name=name)["PublicAccessBlockConfiguration"]
    assert own["BlockPublicPolicy"] is False, (
        f"the access point kept BlockPublicPolicy on: {own!r} — the precedence below would "
        "then prove nothing"
    )

    # S3 counts a grant conditioned on aws:Referer as public; the per-run secret keeps it unusable.
    public = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": f"{ap_arn}/object/*",
                "Condition": {"StringEquals": {"aws:Referer": secrets.token_urlsafe(32)}},
            }
        ],
    })

    # The account-level block is a real singleton (one per account per region) that another
    # concurrent run may already have set, so cleanup must restore whatever was there before
    # rather than unconditionally deleting it. Snapshot it, and register the restore before the
    # write (not after): _ensure_account_pab retries, so an abort inside it must still leave a
    # cleanup behind for the Put that did land.
    original_pab = _get_account_pab(s3c, account)
    ctx.on_cleanup(lambda: _restore_account_pab(s3c, account, original_pab))
    _ensure_account_pab(s3c, account, {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    })

    # The account-level block is eventually consistent: the first PutAccessPointPolicy after
    # PutPublicAccessBlock can still be accepted. Poll for the
    # observable condition (the rejection), and undo any put that slipped through so the
    # effect-absent assertion below is not weakened by it.
    code = code_msg = None
    deadline = _deadline(ctx, 60)
    while True:
        try:
            s3c.put_access_point_policy(AccountId=account, Name=name, Policy=public)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            code_msg = exc.response["Error"].get("Message")
            break
        _drop_ap_policy(s3c, account, name)
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert code == "AccessDenied", (
        f"a public access point policy under the account-level block returned {code!r}, "
        "expected AccessDenied"
    )
    assert code_msg == "Access Denied", (
        f"the refusal carried message {code_msg!r}, expected 'Access Denied'"
    )
    absent, absent_msg = _error(lambda: s3c.get_access_point_policy(AccountId=account, Name=name))
    assert absent == "NoSuchAccessPointPolicy", (
        f"the rejected put left a policy behind: GetAccessPointPolicy returned {absent!r}"
    )
    absent_want = "The specified accesspoint policy does not exist"
    assert absent_msg == absent_want, (
        f"the refusal carried message {absent_msg!r}, expected {absent_want!r}"
    )

    s3c.delete_public_access_block(AccountId=account)
    accepted = False
    deadline = _deadline(ctx, 90)
    while True:
        try:
            s3c.put_access_point_policy(AccountId=account, Name=name, Policy=public)
            accepted = True
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    ctx.on_cleanup(lambda: _drop_ap_policy(s3c, account, name))
    assert accepted, (
        "after DeletePublicAccessBlock the identical public policy was still rejected; "
        "the account-level block behaved as a sticky flag rather than a live evaluation"
    )
    status = s3c.get_access_point_policy_status(AccountId=account, Name=name)["PolicyStatus"]
    assert status["IsPublic"] is True, (
        f"after removing the account block the same document reported {status!r}, "
        "expected IsPublic True"
    )
    stored = json.loads(s3c.get_access_point_policy(AccountId=account, Name=name)["Policy"])
    assert stored["Statement"][0]["Principal"] == {"AWS": "*"}, (
        f"the accepted policy was stored as {stored!r}"
    )


# ===== helpers =====

def _deadline(ctx, seconds: float) -> float:
    """A monotonic deadline ``seconds`` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else max(1.0, min(seconds, left - 5.0)))


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

def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``; raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _get_account_pab(s3c, account: str) -> dict | None:
    """The account-level PublicAccessBlock config, or None if none is set."""
    try:
        return s3c.get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        return None


def _restore_account_pab(s3c, account: str, original: dict | None) -> None:
    try:
        if original is None:
            s3c.delete_public_access_block(AccountId=account)
        else:
            s3c.put_public_access_block(AccountId=account, PublicAccessBlockConfiguration=original)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise


def _drop_ap_policy(s3c, account: str, name: str) -> None:
    try:
        s3c.delete_access_point_policy(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchAccessPointPolicy", "NoSuchAccessPoint"):
            raise


def _drop_access_point(s3c, account: str, name: str) -> None:
    try:
        s3c.delete_access_point(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchAccessPoint":
            raise


def _create_bucket(ctx, s3, name: str) -> None:
    # us-east-1 is S3's implicit default region: CreateBucket rejects a LocationConstraint
    # naming it, so the parameter is only ever passed for any other region.
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
