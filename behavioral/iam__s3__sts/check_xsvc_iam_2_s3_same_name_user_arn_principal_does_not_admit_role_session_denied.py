"""xsvc-iam-2-s3-same-name-user-arn-principal-does-not-admit-role-session-denied."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-2-s3-same-name-user-arn-principal-does-not-admit-role-session-denied"
GROUP = "auth_enforcement"
SERVICES = ["iam", "s3", "sts"]

#: Tags that attribute any resource left behind to this check.
_RES_TAGS = [{"Key": "sim2real", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


# ===== helpers =====
def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _outcome(fn):
    """'OK' when the real signed call succeeds, else its exact AWS error code."""
    code = _error_code(fn)
    return "OK" if code == "UNEXPECTED_SUCCESS" else code


def _settle(probe, want, *, description, streak=3, timeout_s=120, interval_s=2):
    """Poll until probe() returns `want` on `streak` CONSECUTIVE calls.

    IAM is eventually consistent and exposes no API that reports a key or a grant as effective,
    so the operation is its own observable. Settling on the EXACT outcome means a not-yet-live
    access key (InvalidAccessKeyId) can never be read as the authorization verdict.
    """
    deadline = time.monotonic() + timeout_s
    seen, run = [], 0
    while True:
        got = probe()
        seen.append(got)
        run = run + 1 if got == want else 0
        if run >= streak:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: wanted {want!r} {streak}x in a row within {timeout_s}s; "
                f"last observations {seen[-12:]!r}"
            )
        time.sleep(interval_s)


def _policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _purge_user(iam, user):
    """Undo everything a check may have hung on a user, then delete it."""
    for fn in (
        lambda: [iam.delete_user_policy(UserName=user, PolicyName=p)
                 for p in iam.list_user_policies(UserName=user)["PolicyNames"]],
        lambda: [iam.detach_user_policy(UserName=user, PolicyArn=p["PolicyArn"])
                 for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]],
        lambda: [iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"])
                 for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]],
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_user(UserName=user)


def _creds(key_id, secret, token=None):
    return {"aws_access_key_id": key_id, "aws_secret_access_key": secret, "aws_session_token": token}


def _mint_assumer(ctx, iam, account, user_name, role_name):
    """A fresh user whose ONLY permission is sts:AssumeRole on `role_name`; returns (arn, creds)."""
    arn = iam.create_user(UserName=user_name, Tags=_RES_TAGS)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, user_name))
    iam.put_user_policy(UserName=user_name, PolicyName="assume-only", PolicyDocument=_policy({
        "Effect": "Allow", "Action": "sts:AssumeRole",
        "Resource": f"arn:aws:iam::{account}:role/{role_name}",
    }))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    return arn, _creds(key["AccessKeyId"], key["SecretAccessKey"])


def _bare_role(ctx, iam, account, role_name):
    """A role trusted by this account (so an identity Allow is what admits the assumer), with NO
    permissions policy: whatever a session of it can do on S3 comes from the bucket policy."""
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_policy({
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "sts:AssumeRole",
    }), Tags=_RES_TAGS)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _assume(sts_as_user, role_arn, session_name):
    """AssumeRole with a bounded AccessDenied retry at FIRST USE (IAM propagation), nowhere else."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return sts_as_user.assume_role(RoleArn=role_arn, RoleSessionName=session_name,
                                           DurationSeconds=900)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in {"AccessDenied", "InvalidClientTokenId"} and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _bucket(ctx, s3, name):
    create = {"Bucket": name}
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create)

    def _drop():
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=name)
    ctx.on_cleanup(_drop)
    # Tag after registering teardown so a failed PutBucketTagging cannot leave the bucket without
    # cleanup. CreateBucket takes no Tags parameter, so this has to be a second call.
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _RES_TAGS})


def _read(client, bucket, key):
    try:
        return "OK", client.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), None
# ===== end helpers =====


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Bucket-policy principals match on the full ARN, not the trailing name: with a user and a role
    both named N, a session of role N reads only the role-granted prefix and user N only the
    user-granted prefix; each cross read is refused with exactly AccessDenied."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-xsvc-s3sts-sn-")
    bucket = name.lower()
    role_obj, user_obj = "role-granted/probe.bin", "user-granted/probe.bin"
    role_body, user_body = uuid.uuid4().bytes * 8, uuid.uuid4().bytes * 8

    _bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=role_obj, Body=role_body)
    s3.put_object(Bucket=bucket, Key=user_obj, Body=user_body)
    role_arn = _bare_role(ctx, iam, account, name)
    user_arn, user_creds = _mint_assumer(ctx, iam, account, name, name)
    assert (role_arn, user_arn) == (f"arn:aws:iam::{account}:role/{name}",
                                    f"arn:aws:iam::{account}:user/{name}"), (
        f"user and role must share the name {name!r}; got {user_arn!r} and {role_arn!r}"
    )
    sts_as_user = ctx.client("sts", creds=user_creds)
    session = _assume(sts_as_user, role_arn, "probe")

    def grant(sid, principal, prefix):
        return {"Sid": sid, "Effect": "Allow", "Principal": {"AWS": principal},
                "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/{prefix}/*"}

    bucket_policy = _policy(grant("RoleArn", role_arn, "role-granted"),
                            grant("UserArn", user_arn, "user-granted"))
    # A just-created principal can be refused as "Invalid principal" until it propagates to S3.
    _settle(lambda: _outcome(lambda: s3.put_bucket_policy(Bucket=bucket, Policy=bucket_policy)),
            "OK", description="PutBucketPolicy naming user/N and role/N", streak=1)

    c = session["Credentials"]
    as_session = ctx.client("s3", creds=_creds(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]))
    as_user = ctx.client("s3", creds=user_creds)

    # Positive controls first: each principal reads the prefix granted to ITS OWN ARN.
    _settle(lambda: _read(as_session, bucket, role_obj)[0], "OK",
            description="GetObject role-granted/ by the role N session")
    _settle(lambda: _read(as_user, bucket, user_obj)[0], "OK",
            description="GetObject user-granted/ by user N")

    # The negatives: the same-named principal's statement does not admit the other.
    _settle(lambda: _read(as_session, bucket, user_obj)[0], "AccessDenied",
            description="GetObject user-granted/ (Principal user/N) by the role N session")
    _settle(lambda: _read(as_user, bucket, role_obj)[0], "AccessDenied",
            description="GetObject role-granted/ (Principal role/N) by user N")
    for i in range(3):
        grid = {
            "session->role-granted": _read(as_session, bucket, role_obj),
            "session->user-granted": _read(as_session, bucket, user_obj),
            "user->user-granted": _read(as_user, bucket, user_obj),
            "user->role-granted": _read(as_user, bucket, role_obj),
        }
        assert grid == {
            "session->role-granted": ("OK", role_body),
            "session->user-granted": ("AccessDenied", None),
            "user->user-granted": ("OK", user_body),
            "user->role-granted": ("AccessDenied", None),
        }, f"sample {i}: {({k: v[0] for k, v in grid.items()})!r}"

    assert session["AssumedRoleUser"]["Arn"] == f"arn:aws:sts::{account}:assumed-role/{name}/probe", (
        f"session ARN {session['AssumedRoleUser']!r}"
    )
    assert iam.list_role_policies(RoleName=name)["PolicyNames"] == [], "role grew an inline policy"
    assert iam.list_user_policies(UserName=name)["PolicyNames"] == ["assume-only"], (
        "user N must hold only its sts:AssumeRole policy; S3 access must come from the bucket policy"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
