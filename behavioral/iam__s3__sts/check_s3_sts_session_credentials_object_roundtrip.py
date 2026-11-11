"""s3-sts-session-credentials-object-roundtrip."""
# An object written with AssumeRole session credentials lands in the same account's bucket that the
# base identity reads: a session changes the principal, not the world. A target that partitions
# state per access key hands the base identity a different (empty) bucket view.
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-sts-session-credentials-object-roundtrip"
GROUP = "identity"
SERVICES = ["iam", "s3", "sts"]

_RES_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]
_ROLE_PATH = "/sim2real/"
#: Bounded convergence for IAM propagation (trust policy, then the role's permissions).
_PROPAGATE_S = 120.0


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject under AssumeRole session credentials, then the base identity reads identical bytes
    and ETag; the session's GetCallerIdentity is the assumed-role ARN in ctx.account."""
    s3, iam, sts = ctx.client("s3"), ctx.client("iam"), ctx.client("sts")

    bucket = ctx.unique_name("sim2real-s3sts-")
    create: dict = {"Bucket": bucket}
    # us-east-1 rejects an explicit LocationConstraint; every other region requires it.
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create)
    ctx.on_cleanup(_tolerant(lambda: _empty_and_delete(s3, bucket), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _RES_TAGS})

    role_name = ctx.unique_name("sim2real-s3sts-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        Path=_ROLE_PATH,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=_RES_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="object-rw",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    },
                    {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket}"},
                ],
            }
        ),
    )

    session = ctx.unique_name("sim2real-s3sts-")
    creds = _assume(sts, role_arn, session)
    s_s3 = ctx.client("s3", creds=creds)
    s_sts = ctx.client("sts", creds=creds)

    who = s_sts.get_caller_identity()
    partition = role_arn.split(":")[1]
    want_arn = f"arn:{partition}:sts::{ctx.account}:assumed-role/{role_name}/{session}"
    assert who.get("Arn") == want_arn, f"session GetCallerIdentity Arn: expected {want_arn!r}, got {who.get('Arn')!r}"
    assert who.get("Account") == ctx.account, (
        f"session GetCallerIdentity Account: expected {ctx.account!r}, got {who.get('Account')!r}"
    )

    key = f"probe/{ctx.unique_name('obj-')}.bin"
    body = ctx.unique_name("payload-").encode()
    etag = _with_propagation(lambda: s_s3.put_object(Bucket=bucket, Key=key, Body=body))["ETag"]
    assert etag, "session PutObject returned no ETag"
    listed = [o["Key"] for o in s_s3.list_objects_v2(Bucket=bucket, Prefix=key).get("Contents", [])]
    assert listed == [key], f"session ListObjectsV2(Prefix=key): expected [{key!r}], got {listed!r}"

    # Independent read under the BASE identity: the same world, not a per-credential partition.
    got = s3.get_object(Bucket=bucket, Key=key)
    data = got["Body"].read()
    assert data == body, f"base GetObject bytes: expected {body!r}, got {data[:80]!r}"
    assert got["ETag"] == etag, f"base GetObject ETag: expected {etag!r}, got {got['ETag']!r}"

    # Teardown in reverse dependency order, each proven gone.
    s_s3.delete_object(Bucket=bucket, Key=key)
    _gone_bucket(ctx, bucket)
    _gone_role(ctx, role_name)


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message: expected {message!r}, got {msg!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _assume(sts, role_arn: str, session: str) -> dict:
    """AssumeRole, retried only through the trust policy's IAM propagation (AccessDenied)."""
    deadline = time.monotonic() + _PROPAGATE_S
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=session)["Credentials"]
            return {
                "aws_access_key_id": c["AccessKeyId"],
                "aws_secret_access_key": c["SecretAccessKey"],
                "aws_session_token": c["SessionToken"],
            }
        except ClientError as exc:
            if _err(exc)[0] != "AccessDenied" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _with_propagation(fn):
    """``fn()``, retried only while the session's permissions propagate (AccessDenied).

    Any other error is the claim failing: the bucket exists in this account and the role allows it,
    so a not-found means the session credential reached a different world.
    """
    deadline = time.monotonic() + _PROPAGATE_S
    while True:
        try:
            return fn()
        except ClientError as exc:
            code, status, msg = _err(exc)
            if code in ("AccessDenied", "InvalidAccessKeyId") and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise AssertionError(
                f"session PutObject into this account's bucket failed {code!r} HTTP {status!r}: "
                f"{msg[:150]!r}; the session credential is not acting in ctx.account's world"
            ) from exc


def _empty_and_delete(s3, bucket: str) -> None:
    _empty_bucket(s3, bucket)
    s3.delete_bucket(Bucket=bucket)


def _delete_role(iam, role_name: str) -> None:
    """Teardown safety net: inline policies first, then the role; already-gone is fine."""
    try:
        for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if _err(exc)[0] != "NoSuchEntity":
            raise


def _gone_role(ctx, name: str) -> None:
    """Delete the role; GetRole NoSuchEntity naming it, and ListRoles no longer lists it."""
    iam = ctx.client("iam")
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=_ROLE_PATH)}
    assert name in listed, f"ListRoles(PathPrefix={_ROLE_PATH!r}) does not list role {name} before the delete"
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    _poll_refused(lambda: iam.get_role(RoleName=name), ("NoSuchEntity",), 404, f"GetRole {name}",
                  f"The role with name {name} cannot be found.")
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=_ROLE_PATH)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"


def _gone_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    _empty_bucket(s3, bucket)
    s3.delete_bucket(Bucket=bucket)
    # HeadBucket has no body: the code is the bare status.
    _poll_refused(lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket", "NotFound"), 404, f"HeadBucket {bucket}",
                  "Not Found")
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    put = lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x")  # noqa: E731
    _refused(put, ("NoSuchBucket",), 404, f"PutObject {bucket}", "The specified bucket does not exist")
    # S3's NoSuchBucket names the bucket in its own BucketName field.
    try:
        put()
    except ClientError as exc:
        named = exc.response.get("Error", {}).get("BucketName")
        assert named == bucket, f"PutObject NoSuchBucket BucketName: expected {bucket!r}, got {named!r}"


def _empty_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
