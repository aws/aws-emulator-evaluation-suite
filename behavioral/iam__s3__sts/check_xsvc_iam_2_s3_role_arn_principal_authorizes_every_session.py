"""xsvc-iam-2-s3-role-arn-principal-authorizes-every-session."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-2-s3-role-arn-principal-authorizes-every-session"
GROUP = "auth_enforcement"
SERVICES = ["iam", "s3", "sts"]

#: Tags that attribute any leftover resource to this check.
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
    """Poll until probe() returns `want` on `streak` consecutive calls (IAM is eventually
    consistent); settling on the exact outcome keeps InvalidAccessKeyId from reading as a verdict.
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
    # Tagged after teardown is registered so a throttled PutBucketTagging cannot strand the bucket.
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _RES_TAGS})


def _read(client, bucket, key):
    """("OK", body bytes) on success, else (Error.Code, Error.Message)."""
    try:
        return "OK", client.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")


def _denied_message(user_arn, bucket, key):
    """S3's exact implicit-deny message for a same-account IAM user's GetObject."""
    return (
        f"User: {user_arn} is not authorized to perform: s3:GetObject on resource: "
        f'"arn:aws:s3:::{bucket}/{key}" because no identity-based policy allows the s3:GetObject '
        f"action"
    )
# ===== end helpers =====


@tags(
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "axis:happy-path",
)
def run(ctx) -> None:
    """A bucket policy naming a role ARN authorizes every session of that role (any name, minted
    before or after the policy), while the same-account assuming user is refused AccessDenied.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-bucket-user-policy-specifying-principal-intro.html
    """
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    base = ctx.unique_name("sim2real-xsvc-s3sts-ra-")
    role_name, user_name, bucket = base, f"{base}-u", base.lower()
    obj, body = "granted/probe.bin", uuid.uuid4().bytes * 8

    _bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=obj, Body=body)
    role_arn = _bare_role(ctx, iam, account, role_name)
    user_arn, user_creds = _mint_assumer(ctx, iam, account, user_name, role_name)
    sts_as_user = ctx.client("sts", creds=user_creds)

    alpha = _assume(sts_as_user, role_arn, "alpha")
    beta = _assume(sts_as_user, role_arn, "beta")

    bucket_policy = _policy({
        "Sid": "RoleArnPrincipal", "Effect": "Allow", "Principal": {"AWS": role_arn},
        "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
    })
    # A just-created role can be refused as "Invalid principal" until it propagates to S3.
    # The policy goes in before any read: S3 can serve a stale "no policy" denial for 30 s or more
    # to principals that read before it existed.
    _settle(lambda: _outcome(lambda: s3.put_bucket_policy(Bucket=bucket, Policy=bucket_policy)),
            "OK", description="PutBucketPolicy naming the role ARN", streak=1)

    def session_s3(resp):
        c = resp["Credentials"]
        return ctx.client("s3", creds=_creds(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]))

    as_alpha, as_beta = session_s3(alpha), session_s3(beta)
    _settle(lambda: _read(as_alpha, bucket, obj)[0], "OK", description="GetObject by session 'alpha'")
    gamma = _assume(sts_as_user, role_arn, "gamma-minted-after-the-policy")
    as_gamma = session_s3(gamma)
    for label, client in (("alpha", as_alpha), ("beta", as_beta), ("gamma", as_gamma)):
        got = _read(client, bucket, obj)
        assert got == ("OK", body), f"session {label!r} must read the exact bytes; got {got[0]!r}"

    sessions = [alpha, beta, gamma]
    arns = [s["AssumedRoleUser"]["Arn"] for s in sessions]
    keys = {s["Credentials"]["AccessKeyId"] for s in sessions}
    want = [f"arn:aws:sts::{account}:assumed-role/{role_name}/{n}"
            for n in ("alpha", "beta", "gamma-minted-after-the-policy")]
    assert arns == want, f"assumed-role ARNs were {arns!r}, expected {want!r}"
    assert len(keys) == 3, f"three sessions must carry three distinct access keys; got {keys!r}"

    # The minting user is NOT the role: the same GetObject under its own key is refused.
    as_user = ctx.client("s3", creds=user_creds)
    _settle(lambda: _read(as_user, bucket, obj)[0], "AccessDenied",
            description="GetObject by the assuming user, whom the bucket policy does not name")
    for i in range(3):
        pair = (_read(as_alpha, bucket, obj)[0], _read(as_user, bucket, obj))
        assert pair == ("OK", ("AccessDenied", _denied_message(user_arn, bucket, obj))), (
            f"sample {i}: (role session, assuming user) were {pair!r}"
        )
    assert iam.list_role_policies(RoleName=role_name)["PolicyNames"] == [], "role grew an inline policy"
    assert iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"] == [], (
        "role grew an attached policy; the bucket policy would not be the only grant"
    )
    assert user_arn.endswith(f":user/{user_name}"), f"unexpected user ARN {user_arn!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
