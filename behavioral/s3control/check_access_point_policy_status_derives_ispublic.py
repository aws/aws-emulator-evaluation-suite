"""access-point-policy-status-derives-ispublic."""
from __future__ import annotations

import json
import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-point-policy-status-derives-ispublic"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("cap:c7", "concern:representation", "plane:control", "axis:happy-path")
def run(ctx) -> None:
    """GetAccessPointPolicyStatus derives IsPublic from the policy: true for Principal "*", false once
    replaced by an account-principal policy, and no status once the policy is deleted.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-apstat-")
    name = ctx.unique_name("sim2real-behav-apst-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    # The policy blocks have to be off for the service to ACCEPT a public policy at all; the
    # subject here is the derivation, not the block (that is a separate check). ACL blocks stay on.
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
    })

    created = s3c.create_access_point(
        AccountId=account,
        Name=name,
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: s3c.delete_access_point(AccountId=account, Name=name))
    ap_arn = created["AccessPointArn"]

    code, code_msg = _error(lambda: s3c.get_access_point_policy_status(AccountId=account, Name=name))
    assert code == "NoSuchAccessPointPolicy", (
        f"policy status on a policy-less access point returned {code!r}, "
        "expected NoSuchAccessPointPolicy"
    )
    code_want = "The specified accesspoint policy does not exist"
    assert code_msg == code_want, (
        f"the refusal carried message {code_msg!r}, expected {code_want!r}"
    )

    # S3 counts a grant conditioned on aws:Referer as public; the per-run secret keeps it unusable.
    public = {
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
    }
    s3c.put_access_point_policy(AccountId=account, Name=name, Policy=json.dumps(public))
    ctx.on_cleanup(lambda: _drop_ap_policy(s3c, account, name))
    status = s3c.get_access_point_policy_status(AccountId=account, Name=name)["PolicyStatus"]
    assert status["IsPublic"] is True, (
        f"a policy granting Principal AWS:* reported {status!r}, expected IsPublic True"
    )

    scoped = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "s3:GetObject",
                "Resource": f"{ap_arn}/object/*",
            }
        ],
    }
    s3c.put_access_point_policy(AccountId=account, Name=name, Policy=json.dumps(scoped))
    status = s3c.get_access_point_policy_status(AccountId=account, Name=name)["PolicyStatus"]
    assert status["IsPublic"] is False, (
        f"a policy scoped to arn:aws:iam::<account>:root reported {status!r}, "
        "expected IsPublic False — the status must be recomputed from the replacement document"
    )

    read_back = json.loads(s3c.get_access_point_policy(AccountId=account, Name=name)["Policy"])
    principals = [s["Principal"] for s in read_back["Statement"]]
    assert principals == [{"AWS": f"arn:aws:iam::{account}:root"}], (
        f"GetAccessPointPolicy returned principals {principals!r} after the replacement"
    )

    s3c.delete_access_point_policy(AccountId=account, Name=name)
    code, code_msg = _error(lambda: s3c.get_access_point_policy_status(AccountId=account, Name=name))
    assert code == "NoSuchAccessPointPolicy", (
        f"policy status after DeleteAccessPointPolicy returned {code!r}, "
        "expected NoSuchAccessPointPolicy"
    )
    code_want = "The specified accesspoint policy does not exist"
    assert code_msg == code_want, (
        f"the refusal carried message {code_msg!r}, expected {code_want!r}"
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
