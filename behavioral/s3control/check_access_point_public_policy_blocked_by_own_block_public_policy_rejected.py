"""access-point-public-policy-blocked-by-own-block-public-policy-rejected."""
from __future__ import annotations

import json
import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-point-public-policy-blocked-by-own-block-public-policy-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A public policy is rejected on an access point whose own default block blocks public policies,
    leaving no policy behind, while a non-public policy is accepted on the same access point.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-apbpp-")
    blocked = ctx.unique_name("sim2real-behav-apblk-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    # Lift the BUCKET's policy blocks so the only remaining gate is the access point's own; the
    # account's public access block can also decide acceptance and is not under this check's
    # control. ACL blocks stay on.
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
    })

    blocked_arn = s3c.create_access_point(AccountId=account, Name=blocked, Bucket=bucket)[
        "AccessPointArn"
    ]
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, blocked))
    default_pab = s3c.get_access_point(AccountId=account, Name=blocked)[
        "PublicAccessBlockConfiguration"
    ]
    assert default_pab == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }, f"a default access point reported PublicAccessBlockConfiguration {default_pab!r}"

    # S3 counts a grant conditioned on aws:Referer as public; the per-run secret keeps it unusable.
    public = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": f"{blocked_arn}/object/*",
                "Condition": {"StringEquals": {"aws:Referer": secrets.token_urlsafe(32)}},
            }
        ],
    }
    code, code_msg = _error(
        lambda: s3c.put_access_point_policy(
            AccountId=account, Name=blocked, Policy=json.dumps(public)
        )
    )
    assert code == "AccessDenied", (
        f"a public policy on a BlockPublicPolicy access point returned {code!r}, "
        "expected AccessDenied"
    )
    code_want = "Access Denied"
    assert code_msg == code_want, (
        f"the refusal carried message {code_msg!r}, expected {code_want!r}"
    )
    absent, absent_msg = _error(lambda: s3c.get_access_point_policy(AccountId=account, Name=blocked))
    assert absent == "NoSuchAccessPointPolicy", (
        f"the rejected PutAccessPointPolicy left a policy behind: GetAccessPointPolicy "
        f"returned {absent!r}, expected NoSuchAccessPointPolicy"
    )
    absent_want = "The specified accesspoint policy does not exist"
    assert absent_msg == absent_want, (
        f"the refusal carried message {absent_msg!r}, expected {absent_want!r}"
    )

    # Control 1: a scoped policy on the SAME blocked access point is accepted.
    scoped = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "s3:GetObject",
                "Resource": f"{blocked_arn}/object/*",
            }
        ],
    }
    s3c.put_access_point_policy(AccountId=account, Name=blocked, Policy=json.dumps(scoped))
    ctx.on_cleanup(lambda: _drop_ap_policy(s3c, account, blocked))
    status = s3c.get_access_point_policy_status(AccountId=account, Name=blocked)["PolicyStatus"]
    assert status["IsPublic"] is False, (
        f"the accepted scoped policy reported {status!r} on the blocked access point"
    )



def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


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
