"""access-point-prefix-scoped-policy-denies-object-outside-prefix-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-point-prefix-scoped-policy-denies-object-outside-prefix-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A prefix-scoped access point policy is enforced on GetObject via the access point ARN: inside the
    prefix reads, outside is denied until the policy is removed, and the bucket path stays readable.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    bucket = ctx.unique_name("sim2real-behav-apscope-")
    name = ctx.unique_name("sim2real-behav-apsc-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="allowed/inside.txt", Body=b"inside-the-prefix")
    s3.put_object(Bucket=bucket, Key="denied/outside.txt", Body=b"outside-the-prefix")

    ap_arn = s3c.create_access_point(AccountId=account, Name=name, Bucket=bucket)[
        "AccessPointArn"
    ]
    ctx.on_cleanup(lambda: s3c.delete_access_point(AccountId=account, Name=name))

    # Before the policy the access point is a transparent view of the whole bucket.
    body = s3.get_object(Bucket=ap_arn, Key="denied/outside.txt")["Body"].read()
    assert body == b"outside-the-prefix", (
        f"unscoped access point read of denied/outside.txt returned {body!r}"
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowInsidePrefix",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": ["s3:GetObject"],
                "Resource": f"{ap_arn}/object/allowed/*",
            },
            {
                "Sid": "DenyOutsidePrefix",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": ["s3:GetObject"],
                "NotResource": f"{ap_arn}/object/allowed/*",
            },
        ],
    }
    s3c.put_access_point_policy(AccountId=account, Name=name, Policy=json.dumps(policy))
    ctx.on_cleanup(lambda: _drop_ap_policy(s3c, account, name))

    # The policy takes effect within a couple of seconds; poll for the transition rather
    # than sleeping a fixed amount.
    denied_code = denied_msg = None
    for _ in range(20):
        try:
            s3.get_object(Bucket=ap_arn, Key="denied/outside.txt")
        except ClientError as exc:
            denied_code = exc.response["Error"]["Code"]
            denied_msg = exc.response["Error"].get("Message")
            break
        time.sleep(2)
    assert denied_code == "AccessDenied", (
        f"reading denied/outside.txt through the scoped access point gave {denied_code!r}, "
        "expected AccessDenied"
    )
    denied_want = (
        f"User: {caller} is not authorized to perform: s3:GetObject on resource: "
        f'"{ap_arn}/object/denied/outside.txt" with an explicit deny in a resource-based policy'
    )
    assert denied_msg == denied_want, (
        f"the refusal carried message {denied_msg!r}, expected {denied_want!r}"
    )

    inside = s3.get_object(Bucket=ap_arn, Key="allowed/inside.txt")["Body"].read()
    assert inside == b"inside-the-prefix", (
        f"the granted prefix stopped working through the access point: read {inside!r}"
    )

    # The effect is scoped to the access point path only: the bucket itself is untouched.
    direct = s3.get_object(Bucket=bucket, Key="denied/outside.txt")["Body"].read()
    assert direct == b"outside-the-prefix", (
        f"the access point policy leaked onto the bucket path: direct read gave {direct!r}"
    )

    # Restore: the deny was the policy's doing, not something else about the access point.
    # Removing it must lift the deny on the identical call that was just rejected.
    _drop_ap_policy(s3c, account, name)
    policy_gone = policy_gone_msg = None
    for _ in range(20):
        try:
            s3c.get_access_point_policy(AccountId=account, Name=name)
        except ClientError as exc:
            policy_gone = exc.response["Error"]["Code"]
            policy_gone_msg = exc.response["Error"].get("Message")
            break
        time.sleep(2)
    assert policy_gone == "NoSuchAccessPointPolicy", (
        f"after deleting it, GetAccessPointPolicy reported {policy_gone!r}, "
        "expected NoSuchAccessPointPolicy"
    )
    assert policy_gone_msg == "The specified accesspoint policy does not exist", (
        f"after deleting it, GetAccessPointPolicy carried message {policy_gone_msg!r}"
    )

    restored = None
    deadline = _deadline(ctx, 500)
    while True:
        try:
            restored = s3.get_object(Bucket=ap_arn, Key="denied/outside.txt")["Body"].read()
            break
        except ClientError:
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
    assert restored == b"outside-the-prefix", (
        f"removing the deny policy must restore the identical read that was just rejected; "
        f"got {restored!r}"
    )



def _deadline(ctx, seconds: float) -> float:
    """A monotonic deadline ``seconds`` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else max(1.0, min(seconds, left - 5.0)))


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
