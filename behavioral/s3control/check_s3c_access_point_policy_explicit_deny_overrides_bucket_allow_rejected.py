"""s3c-access-point-policy-explicit-deny-overrides-bucket-allow-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3c-access-point-policy-explicit-deny-overrides-bucket-allow-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]

_OPEN_KEY = "open/allowed.txt"
_LOCKED_KEY = "locked/secret.txt"
_OPEN_BODY = b"readable through the access point\n"
_LOCKED_BODY = b"readable only off the access point path\n"


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An access point policy's explicit Deny beats the bucket policy's Allow on that path only:
    the denied key is refused via the access point but served via the bucket, and an
    un-denied key is still served through the access point."""
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    caller = ctx.client("sts").get_caller_identity()["Arn"]

    bucket = ctx.unique_name("sim2real-behav-apden-")
    ap = ctx.unique_name("sim2real-behav-apdenap-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key=_OPEN_KEY, Body=_OPEN_BODY)
    s3.put_object(Bucket=bucket, Key=_LOCKED_KEY, Body=_LOCKED_BODY)

    # The bucket policy allows GetObject on EVERY key for this account, so the bucket half of the
    # decision is an unconditional Allow for both keys. Neither statement is public (the principal
    # is this account's root ARN), so account-level block-public-access does not refuse it.
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowAccountRead",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_bucket_policy(s3, bucket))

    ap_arn = s3c.create_access_point(AccountId=account, Name=ap, Bucket=bucket)["AccessPointArn"]
    ctx.on_cleanup(lambda: s3c.delete_access_point(AccountId=account, Name=ap))

    # Exactly ONE thing is broken for the locked prefix: the access point policy denies it. The
    # same document allows every other key, which is what makes the positive control below a
    # control rather than a second estate.
    s3c.put_access_point_policy(
        AccountId=account,
        Name=ap,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowAllThroughAccessPoint",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "s3:GetObject",
                        "Resource": f"{ap_arn}/object/*",
                    },
                    {
                        "Sid": "DenyLockedPrefix",
                        "Effect": "Deny",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "s3:GetObject",
                        "Resource": f"{ap_arn}/object/locked/*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_access_point_policy(s3c, account, ap))

    stored = json.loads(s3c.get_access_point_policy(AccountId=account, Name=ap)["Policy"])
    effects = {s["Sid"]: s["Effect"] for s in stored["Statement"]}
    assert effects == {"AllowAllThroughAccessPoint": "Allow", "DenyLockedPrefix": "Deny"}, (
        f"the stored access point policy reads {effects!r}, expected one Allow and one Deny"
    )

    # A resource policy becomes effective a short moment after the PUT; poll the observable
    # decision rather than sleeping. A GET that never stops succeeding is the over-permissiveness
    # this check exists to catch, and it is reported as such below.
    denied = denied_msg = None
    deadline = _deadline(ctx, 75)
    while True:
        try:
            s3.get_object(Bucket=ap_arn, Key=_LOCKED_KEY)
        except ClientError as exc:
            denied = exc.response["Error"]["Code"]
            denied_msg = exc.response["Error"].get("Message")
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert denied == "AccessDenied", (
        f"reading {_LOCKED_KEY!r} through the access point produced {denied!r}, expected "
        "'AccessDenied' from the access point policy's explicit Deny (None means the read kept "
        "succeeding for 75s, i.e. the Deny was never applied)"
    )
    denied_want = (
        f"User: {caller} is not authorized to perform: s3:GetObject on resource: "
        f'"{ap_arn}/object/{_LOCKED_KEY}" with an explicit deny in a resource-based policy'
    )
    assert denied_msg == denied_want, (
        f"the refusal carried message {denied_msg!r}, expected {denied_want!r}"
    )

    # The effect of the denial is an ABSENCE of bytes, and the object itself is untouched: the
    # same key read straight from the bucket still returns its original content, which is what
    # makes this a scoping result rather than a deleted object.
    assert s3.get_object(Bucket=bucket, Key=_LOCKED_KEY)["Body"].read() == _LOCKED_BODY, (
        f"reading {_LOCKED_KEY!r} directly from the bucket no longer returns its original bytes; "
        "the access point Deny must not change the object or the bucket path"
    )

    # Positive control, same file, same policy document, same principal: the key the Deny does not
    # name is still served through the access point, byte for byte.
    served = s3.get_object(Bucket=ap_arn, Key=_OPEN_KEY)["Body"].read()
    assert served == _OPEN_BODY, (
        f"reading {_OPEN_KEY!r} through the access point returned {served!r}, expected "
        f"{_OPEN_BODY!r} — the Allow statement must still be honoured"
    )


# ===== helpers =====

def _deadline(ctx, seconds: float) -> float:
    """A monotonic deadline ``seconds`` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else max(1.0, min(seconds, left - 5.0)))


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
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
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


def _delete_bucket_policy(s3, bucket: str) -> None:
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchBucketPolicy"):
            raise


def _delete_access_point_policy(s3c, account: str, ap: str) -> None:
    try:
        s3c.delete_access_point_policy(AccountId=account, Name=ap)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchAccessPointPolicy", "NoSuchAccessPoint"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
