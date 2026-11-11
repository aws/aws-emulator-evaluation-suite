"""account-public-access-block-restrict-denies-anonymous-object-read-rejected."""
from __future__ import annotations

import json
import secrets
import time

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-public-access-block-restrict-denies-anonymous-object-read-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data", "resource:account-singleton:s3-account-public-access-block")
def run(ctx) -> None:
    """RestrictPublicBuckets blocks anonymous reads of a public bucket without editing its policy.

    The owner's signed read still works, GetBucketPolicy returns the identical document with
    IsPublic=true, and lifting the flag restores the same anonymous read.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-pabanon-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    # The bucket's own block allows the public policy and its use; its ACL blocks stay on.
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_object(Bucket=bucket, Key="open.txt", Body=b"anonymously-readable")

    # S3 classifies a grant to "*" conditioned on aws:Referer as public; only unsigned requests
    # carrying this per-run secret can use it.
    referer = secrets.token_urlsafe(32)
    public = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"aws:Referer": referer}},
            }
        ],
    })
    s3.put_bucket_policy(Bucket=bucket, Policy=public)
    ctx.on_cleanup(lambda: _drop_bucket_policy(s3, bucket))

    anon = _anon_client(ctx, referer)
    body = None
    poll_deadline = _poll_deadline(ctx, 60.0)
    while time.monotonic() < poll_deadline:
        try:
            body = anon.get_object(Bucket=bucket, Key="open.txt")["Body"].read()
            break
        except ClientError:
            time.sleep(2)
    assert body == b"anonymously-readable", (
        f"the baseline anonymous read never succeeded (last body {body!r}); "
        "the restriction below would prove nothing"
    )

    # BlockPublicPolicy stays FALSE so the policy is not touched — only its effect is.
    # The account-level block is a one-per-account record: snapshot what is there and restore
    # exactly that. Registered before the write, not after: _ensure_account_pab retries, so an
    # abort inside it must still leave a restore behind for the Put that did land.
    original_pab = _read_account_pab(s3c, account)
    ctx.on_cleanup(lambda: _restore_account_pab(s3c, account, original_pab))
    _ensure_account_pab(s3c, account, {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": True,
    })

    denied = None
    poll_deadline = _poll_deadline(ctx, 60.0)
    while time.monotonic() < poll_deadline:
        try:
            anon.get_object(Bucket=bucket, Key="open.txt")
        except ClientError as exc:
            denied = exc.response["Error"]
            break
        time.sleep(2)
    assert denied is not None, (
        "the anonymous read kept succeeding for 60s under RestrictPublicBuckets"
    )
    assert denied.get("Code") == "AccessDenied", (
        f"the anonymous read under RestrictPublicBuckets returned {denied!r}, "
        "expected AccessDenied"
    )
    assert denied.get("Message") == "Access Denied", (
        f"the anonymous read under RestrictPublicBuckets was refused with message "
        f"{denied.get('Message')!r}"
    )

    owner = s3.get_object(Bucket=bucket, Key="open.txt")["Body"].read()
    assert owner == b"anonymously-readable", (
        f"the owner's signed read broke under RestrictPublicBuckets: {owner!r}"
    )

    stored = s3.get_bucket_policy(Bucket=bucket)["Policy"]
    assert json.loads(stored) == json.loads(public), (
        f"RestrictPublicBuckets rewrote the bucket policy to {stored!r}"
    )
    assert s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"] is True, (
        "GetBucketPolicyStatus stopped reporting the policy as public — the flag restricts "
        "the effect, it does not reclassify the document"
    )

    # Restore: lift RestrictPublicBuckets and demand the IDENTICAL anonymous read succeed
    # again, on the same object and policy. A target that implements the flag as a one-time
    # scrub rather than a live evaluation would stay blocked here.
    _ensure_account_pab(s3c, account, {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    })
    restored = None
    # Lifting the account-level block reaches the S3 data plane eventually, more slowly than
    # setting it, so the restored read is polled for up to 300 s.
    poll_deadline = _poll_deadline(ctx, 300.0)
    while time.monotonic() < poll_deadline:
        try:
            restored = anon.get_object(Bucket=bucket, Key="open.txt")["Body"].read()
            break
        except ClientError:
            time.sleep(2)
    assert restored == b"anonymously-readable", (
        f"the anonymous read stayed blocked after RestrictPublicBuckets was turned back off "
        f"(last body {restored!r}); the restriction behaved as a sticky scrub rather than a "
        "live evaluation"
    )


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

def _anon_client(ctx, referer: str):
    """An S3 client that sends NO SigV4 signature and the given Referer, aimed at the same target
    as ctx."""
    client = ctx.client(
        "s3", config=Config(signature_version=UNSIGNED, retries={"max_attempts": 1})
    )
    client.meta.events.register(
        "before-sign.s3.GetObject",
        lambda request, **_: request.headers.__setitem__("Referer", referer),
    )
    return client


def _read_account_pab(s3c, account: str) -> dict | None:
    """The account-level PublicAccessBlock as it stands, or None when none is configured."""
    try:
        return s3c.get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        return None


def _restore_account_pab(s3c, account: str, original: dict | None) -> None:
    """Put back exactly the account-level block that existed before the check ran, then poll every
    2 s until GetPublicAccessBlock serves it; raise if it never does within the deadline."""
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
    served = _read_account_pab(s3c, account)
    while served != original:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the account-level PublicAccessBlock was not restored to {original!r}; "
                f"GetPublicAccessBlock still serves {served!r}"
            )
        time.sleep(2)
        served = _read_account_pab(s3c, account)


def _drop_bucket_policy(s3, bucket: str) -> None:
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket",):
            raise


def _create_bucket(ctx, s3, name: str) -> None:
    params: dict = {"Bucket": name}
    # us-east-1 is CreateBucket's own default region and rejects an explicit
    # LocationConstraint for it.
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str) -> None:
    """Empty and delete the bucket; NoSuchBucket is done, BucketNotEmpty re-empties to a deadline."""
    deadline = time.monotonic() + 300.0
    while True:
        try:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
                objs = [
                    {"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
                ]
                if objs:
                    s3.delete_objects(Bucket=name, Delete={"Objects": objs})
            s3.delete_bucket(Bucket=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _poll_deadline(ctx, cap_s: float) -> float:
    """A poll's monotonic deadline: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return time.monotonic() + (cap_s if left is None else max(1.0, min(cap_s, left - 5.0)))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
