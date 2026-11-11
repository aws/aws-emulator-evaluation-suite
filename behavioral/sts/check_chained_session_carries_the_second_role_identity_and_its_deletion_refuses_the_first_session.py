"""chained-session-carries-the-second-role-identity-and-its-deletion-refuses-the-first-session."""

from __future__ import annotations

import datetime as _dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "chained-session-carries-the-second-role-identity-and-its-deletion-refuses-the-first-session"
)
GROUP = "e2e"
SERVICES = ["sts"]

_DURATION_S = 1200
_EXPIRY_SLACK_S = 120
_BODY = b"chained-session-object\n" * 77
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
    """A session of one role assumes a second role: the chained credentials resolve to the second
    role's session and sign S3 work the base principal reads back; deleting the second role makes
    the first session's AssumeRole refuse with AccessDenied naming that session as the caller."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    s3 = ctx.client("s3")
    account = ctx.account
    base_identity = sts.get_caller_identity()
    assert base_identity["Account"] == account, (
        f"GetCallerIdentity reports account {base_identity['Account']!r}, expected {account!r}"
    )
    partition = base_identity["Arn"].split(":")[1]
    bucket = ctx.unique_name("sim2real-behav-chain-")

    first = ctx.unique_name("sim2real-behav-first-")
    second = ctx.unique_name("sim2real-behav-second-")
    first_arn = f"arn:{partition}:iam::{account}:role/{first}"
    second_arn = f"arn:{partition}:iam::{account}:role/{second}"
    # Both roles trust the account; the first role's identity policy is what lets its session chain.
    account_root = {"AWS": f"arn:{partition}:iam::{account}:root"}
    first_id = _create_role(ctx, iam, first, account_root)
    _put_policy(
        ctx, iam, first, {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": second_arn}
    )
    second_id = _create_role(ctx, iam, second, account_root)
    _put_policy(
        ctx,
        iam,
        second,
        {
            "Effect": "Allow",
            "Action": ["s3:CreateBucket", "s3:PutObject"],
            "Resource": [f"arn:{partition}:s3:::{bucket}", f"arn:{partition}:s3:::{bucket}/*"],
        },
    )

    first_session = ctx.unique_name("hop1-")
    hop1 = _poll(
        lambda: _try_assume(sts, RoleArn=first_arn, RoleSessionName=first_session),
        lambda r: r is not None,
        timeout_s=40,
        interval_s=3,
        what="the first role becomes assumable",
    )
    first_sts = _client_from(ctx, "sts", hop1["Credentials"])
    first_session_arn = f"arn:{partition}:sts::{account}:assumed-role/{first}/{first_session}"
    assert hop1["AssumedRoleUser"]["Arn"] == first_session_arn, (
        f"first hop Arn {hop1['AssumedRoleUser']['Arn']!r}"
    )

    second_session = ctx.unique_name("hop2-")
    hop2 = _poll(
        lambda: _try_assume(
            first_sts,
            RoleArn=second_arn,
            RoleSessionName=second_session,
            DurationSeconds=_DURATION_S,
        ),
        lambda r: r is not None,
        timeout_s=40,
        interval_s=3,
        what="the first session can assume the second role",
    )
    _assert_expiration(hop2["Credentials"], _DURATION_S)
    second_session_arn = f"arn:{partition}:sts::{account}:assumed-role/{second}/{second_session}"
    expected_user = {"Arn": second_session_arn, "AssumedRoleId": f"{second_id}:{second_session}"}
    assert hop2["AssumedRoleUser"] == expected_user, (
        f"chained AssumedRoleUser {hop2['AssumedRoleUser']!r}, expected {expected_user!r}"
    )

    second_sts = _client_from(ctx, "sts", hop2["Credentials"])
    second_s3 = _client_from(ctx, "s3", hop2["Credentials"])
    ident = _first_identity(second_sts)
    assert (ident["Arn"], ident["UserId"], ident["Account"]) == (
        second_session_arn,
        f"{second_id}:{second_session}",
        account,
    ), f"chained session GetCallerIdentity {ident!r}"
    still_first = _first_identity(first_sts)
    assert (still_first["Arn"], still_first["UserId"]) == (
        first_session_arn,
        f"{first_id}:{first_session}",
    ), f"the first session resolves to {still_first!r} after chaining"

    create_kwargs = {"Bucket": bucket}
    # us-east-1 is the S3 region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    _poll(
        lambda: _try_s3(second_s3.create_bucket, **create_kwargs),
        lambda ok: ok,
        timeout_s=40,
        interval_s=3,
        what="the chained session can create its bucket",
    )
    ctx.on_cleanup(lambda: _delete_bucket_if_exists(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    second_s3.put_object(Bucket=bucket, Key="chained.txt", Body=_BODY)
    got = s3.get_object(Bucket=bucket, Key="chained.txt")["Body"].read()
    assert got == _BODY, (
        f"the chained session's object reads back {len(got)} bytes, expected {len(_BODY)}"
    )
    s3.delete_object(Bucket=bucket, Key="chained.txt")
    s3.delete_bucket(Bucket=bucket)

    iam.delete_role_policy(RoleName=second, PolicyName="sim2real-inline")
    iam.delete_role(RoleName=second)
    code, message, status = _poll(
        lambda: _assume_outcome(first_sts, second_arn, ctx.unique_name("hop2b-")),
        lambda r: r != _SUCCEEDED,
        timeout_s=35,
        interval_s=2,
        what="the first session's AssumeRole on the deleted role is refused",
    )
    denied = (
        "AccessDenied",
        f"User: {first_session_arn} is not authorized to perform: sts:AssumeRole on resource: {second_arn}",
    )
    assert (code, message) == denied, (
        f"chained AssumeRole on a deleted role answered {(code, message)!r}, expected {denied}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"refusal was HTTP {status!r}, not 4xx"
    after = second_sts.get_caller_identity()
    assert after["Arn"] == second_session_arn, (
        f"the issued chained session resolves to {after['Arn']!r}"
    )


def _create_role(ctx, iam, name, principal):
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}],
    }
    role_id = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["RoleId"]
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, name))
    return role_id


def _put_policy(ctx, iam, role, statement):
    iam.put_role_policy(
        RoleName=role,
        PolicyName="sim2real-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
    )
    ctx.on_cleanup(lambda: _delete_role_policy_if_exists(iam, role, "sim2real-inline"))


def _assert_expiration(creds, duration_s) -> None:
    assert (
        creds.get("AccessKeyId") and creds.get("SecretAccessKey") and creds.get("SessionToken")
    ), "the chained AssumeRole returned incomplete credentials"
    expiration = creds["Expiration"]
    if isinstance(expiration, str):
        expiration = _dt.datetime.fromisoformat(expiration.replace("Z", "+00:00"))
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=_dt.timezone.utc)
    remaining = (expiration - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    assert abs(remaining - duration_s) <= _EXPIRY_SLACK_S, (
        f"chained Expiration is {remaining:.0f}s from now, expected {duration_s}s +/- {_EXPIRY_SLACK_S}s"
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


def _assume_outcome(sts, role_arn, session):
    """(code, message, HTTP status) once AssumeRole is refused; _SUCCEEDED while it succeeds."""
    try:
        sts.assume_role(RoleArn=role_arn, RoleSessionName=session)
    except ClientError as e:
        err = e.response.get("Error", {})
        return (
            err.get("Code"),
            err.get("Message"),
            e.response["ResponseMetadata"].get("HTTPStatusCode"),
        )
    return _SUCCEEDED


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
