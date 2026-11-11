"""assumed-role-arn-omits-the-role-path-and-honours-a-raised-max-session-duration."""

from __future__ import annotations

import datetime as _dt
import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assumed-role-arn-omits-the-role-path-and-honours-a-raised-max-session-duration"
GROUP = "e2e"
SERVICES = ["sts"]

_MAX_SESSION_S = 7200
_EXPIRY_SLACK_S = 120
_KEY = "reports/q4/ü-data.bin"
#: What an error probe answers while the call still succeeds.
_SUCCEEDED = ("succeeded", "the call succeeded", 200)


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:e2e",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A role under a nested path with a raised MaxSessionDuration issues a session for the full
    duration whose assumed-role ARN drops the path, refuses one second more, signs S3 work the base
    principal reads back byte-exact, and once deleted refuses AssumeRole naming its pathed ARN."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    s3 = ctx.client("s3")
    account = ctx.account

    base_identity = sts.get_caller_identity()
    assert base_identity["Account"] == account, (
        f"GetCallerIdentity reports account {base_identity['Account']!r}, expected {account!r}"
    )
    partition = base_identity["Arn"].split(":")[1]

    role_name = ctx.unique_name("sim2real-behav-pathed-")
    path = f"/team/{ctx.unique_name('t-')}/svc/"
    bucket = ctx.unique_name("sim2real-behav-stsp-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    created = iam.create_role(
        RoleName=role_name,
        Path=path,
        MaxSessionDuration=_MAX_SESSION_S,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, role_name))
    role_arn = created["Arn"]
    assert role_arn == f"arn:{partition}:iam::{account}:role{path}{role_name}", (
        f"CreateRole Arn {role_arn!r} does not carry the path {path!r}"
    )
    role_id = created["RoleId"]
    permissions = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:CreateBucket", "s3:PutObject"],
                "Resource": [f"arn:{partition}:s3:::{bucket}", f"arn:{partition}:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-bucket", PolicyDocument=json.dumps(permissions)
    )
    ctx.on_cleanup(lambda: _delete_role_policy_if_exists(iam, role_name, "sim2real-bucket"))

    # Session names may carry = , . @ - besides word characters.
    session = f"svc.{ctx.unique_name('')}@ops=1,a-b"
    assumed = _poll(
        lambda: _try_assume(
            sts, RoleArn=role_arn, RoleSessionName=session, DurationSeconds=_MAX_SESSION_S
        ),
        lambda r: r is not None,
        timeout_s=40,
        interval_s=3,
        what="the new role becomes assumable",
    )
    creds = assumed["Credentials"]
    _assert_temporary_credentials(creds, "AssumeRole", _MAX_SESSION_S)
    # The assumed-role ARN names the role without its path.
    expected_arn = f"arn:{partition}:sts::{account}:assumed-role/{role_name}/{session}"
    expected_user_id = f"{role_id}:{session}"
    user = assumed["AssumedRoleUser"]
    assert (user["Arn"], user["AssumedRoleId"]) == (expected_arn, expected_user_id), (
        f"AssumedRoleUser {user!r}, expected Arn {expected_arn!r} and AssumedRoleId {expected_user_id!r}"
    )

    # One second over the role's MaxSessionDuration is refused.
    code, message, status = _assume_outcome(
        sts, role_arn, ctx.unique_name("over-"), _MAX_SESSION_S + 1
    )
    over = (
        "ValidationError",
        "The requested DurationSeconds exceeds the MaxSessionDuration set for this role.",
    )
    assert (code, message) == over, (
        f"AssumeRole for {_MAX_SESSION_S + 1}s answered {(code, message)!r}, expected {over}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"refusal was HTTP {status!r}, not 4xx"

    temp_sts = _client_from(ctx, "sts", creds)
    temp_s3 = _client_from(ctx, "s3", creds)
    ident = _first_identity(temp_sts)
    assert (ident["Arn"], ident["UserId"], ident["Account"]) == (
        expected_arn,
        expected_user_id,
        account,
    ), f"session GetCallerIdentity {ident!r}"
    create_kwargs = {"Bucket": bucket}
    # us-east-1 is the S3 region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    _poll(
        lambda: _try_s3(temp_s3.create_bucket, **create_kwargs),
        lambda ok: ok,
        timeout_s=40,
        interval_s=3,
        what="the session can create its bucket",
    )
    ctx.on_cleanup(lambda: _delete_bucket_if_exists(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    body = secrets.token_bytes(3001)
    temp_s3.put_object(Bucket=bucket, Key=_KEY, Body=body)
    got = s3.get_object(Bucket=bucket, Key=_KEY)
    data = got["Body"].read()
    assert (got["ContentLength"], data) == (len(body), body), (
        f"the object written with session credentials reads back {len(data)} bytes, expected the "
        f"{len(body)} random bytes written"
    )
    s3.delete_object(Bucket=bucket, Key=_KEY)
    s3.delete_bucket(Bucket=bucket)

    iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-bucket")
    iam.delete_role(RoleName=role_name)
    gone = _poll(
        lambda: _get_role_error(iam, role_name),
        lambda r: r != _SUCCEEDED,
        timeout_s=30,
        interval_s=2,
        what="GetRole refuses the deleted role",
    )
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    assert gone[:2] == role_gone and 400 <= (gone[2] or 0) < 500, (
        f"GetRole on the deleted role answered {gone!r}, expected {role_gone} and 4xx"
    )
    code, message, status = _poll(
        lambda: _assume_outcome(sts, role_arn, ctx.unique_name("sess2-"), 900),
        lambda r: r != _SUCCEEDED,
        timeout_s=35,
        interval_s=2,
        what="AssumeRole on the deleted role is refused",
    )
    denied = (
        "AccessDenied",
        f"User: {base_identity['Arn']} is not authorized to perform: sts:AssumeRole on resource: {role_arn}",
    )
    assert (code, message) == denied, (
        f"AssumeRole on a deleted role answered {(code, message)!r}, expected {denied}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"refusal was HTTP {status!r}, not 4xx"

    after = temp_sts.get_caller_identity()
    assert (after["Arn"], after["UserId"]) == (expected_arn, expected_user_id), (
        f"the issued session resolves to {after!r} after the role was deleted"
    )


def _assert_temporary_credentials(creds, op, duration_s) -> None:
    assert len(creds.get("AccessKeyId") or "") >= 16, f"{op} returned no usable AccessKeyId"
    assert creds.get("SecretAccessKey"), f"{op} returned an empty SecretAccessKey"
    assert creds.get("SessionToken"), f"{op} returned an empty SessionToken"
    expiration = creds["Expiration"]
    if isinstance(expiration, str):
        expiration = _dt.datetime.fromisoformat(expiration.replace("Z", "+00:00"))
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=_dt.timezone.utc)
    remaining = (expiration - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    assert abs(remaining - duration_s) <= _EXPIRY_SLACK_S, (
        f"{op} Expiration is {remaining:.0f}s from now, expected {duration_s}s +/- {_EXPIRY_SLACK_S}s"
    )


def _client_from(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll(probe, done, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if done(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")


def _first_identity(sts):
    """GetCallerIdentity with credentials just issued, retried while the new session token is
    still propagating (InvalidClientTokenId)."""

    def probe():
        try:
            return sts.get_caller_identity()
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidClientTokenId":
                return None
            raise

    return _poll(
        probe,
        lambda r: r is not None,
        timeout_s=40,
        interval_s=2,
        what="the new session's credentials are accepted",
    )


def _try_assume(sts, **kwargs):
    """AssumeRole's response, or None while the new trust is still propagating (AccessDenied)."""
    try:
        return sts.assume_role(**kwargs)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        # A just-issued caller session can also be refused as an unknown token while it propagates.
        if code == "AccessDenied" or code == "InvalidClientTokenId":
            return None
        raise


def _try_s3(call, **kwargs) -> bool:
    """True once the call succeeds; False while the session's new policy or its new access key
    is still propagating to S3."""
    try:
        call(**kwargs)
        return True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AccessDenied" or code == "InvalidAccessKeyId":
            return False
        raise


def _assume_outcome(sts, role_arn, session, duration_s):
    """(code, message, HTTP status) once AssumeRole is refused; _SUCCEEDED while it succeeds."""
    try:
        sts.assume_role(RoleArn=role_arn, RoleSessionName=session, DurationSeconds=duration_s)
    except ClientError as e:
        err = e.response.get("Error", {})
        return (
            err.get("Code"),
            err.get("Message"),
            e.response["ResponseMetadata"].get("HTTPStatusCode"),
        )
    return _SUCCEEDED


def _get_role_error(iam, role_name):
    """(code, message, HTTP status) of GetRole's error, or _SUCCEEDED while the role reads back."""
    try:
        iam.get_role(RoleName=role_name)
        return _SUCCEEDED
    except ClientError as e:
        err = e.response.get("Error", {})
        return (
            err.get("Code"),
            err.get("Message"),
            e.response["ResponseMetadata"].get("HTTPStatusCode"),
        )


def _delete_role_policy_if_exists(iam, role_name, policy_name) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_if_exists(iam, role_name) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_bucket_if_exists(s3, bucket) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
