"""xsvc-iam-2-s3-session-arn-principal-admits-only-that-session-denied."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-2-s3-session-arn-principal-admits-only-that-session-denied"
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
    """("OK", body bytes) on success, else (Error.Code, Error.Message)."""
    try:
        return "OK", client.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
# ===== end helpers =====


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A bucket policy naming an assumed-role session ARN admits only that session name: two separately
    minted 'alpha' sessions read the object's exact bytes, while a 'beta' session of the same role
    is refused with exactly AccessDenied."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    base = ctx.unique_name("sim2real-xsvc-s3sts-sa-")
    role_name, user_name, bucket = base, f"{base}-u", base.lower()
    obj, body = "pinned/probe.bin", uuid.uuid4().bytes * 8

    _bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=obj, Body=body)
    role_arn = _bare_role(ctx, iam, account, role_name)
    _user_arn, user_creds = _mint_assumer(ctx, iam, account, user_name, role_name)
    sts_as_user = ctx.client("sts", creds=user_creds)

    alpha = _assume(sts_as_user, role_arn, "alpha")
    beta = _assume(sts_as_user, role_arn, "beta")
    pinned = f"arn:aws:sts::{account}:assumed-role/{role_name}/alpha"
    assert alpha["AssumedRoleUser"]["Arn"] == pinned, f"alpha session ARN {alpha['AssumedRoleUser']!r}"
    assert beta["AssumedRoleUser"]["Arn"] == f"arn:aws:sts::{account}:assumed-role/{role_name}/beta", (
        f"beta session ARN {beta['AssumedRoleUser']!r}"
    )

    bucket_policy = _policy({
        "Sid": "SessionArnPrincipal", "Effect": "Allow", "Principal": {"AWS": pinned},
        "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
    })
    _settle(lambda: _outcome(lambda: s3.put_bucket_policy(Bucket=bucket, Policy=bucket_policy)),
            "OK", description="PutBucketPolicy naming the alpha session ARN", streak=1)
    stored = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])["Statement"]
    assert [s["Principal"] for s in stored] == [{"AWS": pinned}], (
        f"S3 must store the session ARN principal verbatim; got {stored!r}"
    )

    def session_s3(resp):
        c = resp["Credentials"]
        return ctx.client("s3", creds=_creds(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]))

    as_alpha, as_beta = session_s3(alpha), session_s3(beta)

    # Positive control first: the pinned session reads.
    _settle(lambda: _read(as_alpha, bucket, obj)[0], "OK", description="GetObject by the pinned session")
    got = _read(as_alpha, bucket, obj)
    assert got == ("OK", body), f"the pinned session must read the exact bytes; got {got[0]!r}"

    # The negative: same role, same minting user, different session name.
    _settle(lambda: _read(as_beta, bucket, obj)[0], "AccessDenied",
            description="GetObject by a second session of the same role with a different name")

    # Same session NAME, freshly minted credential: admitted, because the ARN matches.
    alpha2 = _assume(sts_as_user, role_arn, "alpha")
    as_alpha2 = session_s3(alpha2)
    assert alpha2["AssumedRoleUser"]["Arn"] == pinned, f"re-minted alpha ARN {alpha2['AssumedRoleUser']!r}"
    assert alpha2["Credentials"]["AccessKeyId"] != alpha["Credentials"]["AccessKeyId"], (
        "the re-minted alpha session must carry a different access key"
    )
    beta_denied = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/beta is not authorized to perform: "
        f's3:GetObject on resource: "arn:aws:s3:::{bucket}/{obj}" because no identity-based policy '
        f"allows the s3:GetObject action"
    )
    for i in range(3):
        trio = (_read(as_alpha, bucket, obj), _read(as_alpha2, bucket, obj), _read(as_beta, bucket, obj))
        assert [t[0] for t in trio] == ["OK", "OK", "AccessDenied"] and trio[:2] == (("OK", body),) * 2, (
            f"sample {i}: (alpha, re-minted alpha, beta) were {[t[0] for t in trio]!r}; expected "
            f"['OK', 'OK', 'AccessDenied']"
        )
        beta_message = trio[2][1]
        assert beta_message == beta_denied, (
            f"sample {i}: expected message {beta_denied!r}, got {beta_message!r}"
        )
    assert iam.list_role_policies(RoleName=role_name)["PolicyNames"] == [], "role grew an inline policy"
    assert iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"] == [], (
        "role grew an attached policy; the bucket policy would not be the only grant"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
