"""e2e-role-lifecycle-assume-use-delete-revokes-future-assumption."""
from __future__ import annotations

import datetime as _dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-role-lifecycle-assume-use-delete-revokes-future-assumption"
GROUP = "e2e"
SERVICES = ["sts"]

_DURATION_S = 900
_EXPIRY_SLACK_S = 120
_TAG_KEY = "sim2real-team"
_TAG_VALUE = "journey"
_BODY = b"written-with-assumed-role-credentials\n" * 32
#: What an error probe answers while the call still succeeds.
_SUCCEEDED = ("succeeded", "the call succeeded", 200)


@tags("axis:happy-path", "cap:c1", "concern:e2e", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """Temporary credentials from AssumeRole and GetSessionToken have AWS's shape and identity and
    sign real S3 work; deleting the role refuses new sessions while an issued one still resolves."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    s3 = ctx.client("s3")
    account = ctx.account

    base_identity = sts.get_caller_identity()
    assert base_identity["Account"] == account, (
        f"GetCallerIdentity reports account {base_identity['Account']!r}, expected {account!r}"
    )
    # Every expected ARN carries the caller's own partition, never a literal 'aws'.
    partition = base_identity["Arn"].split(":")[1]

    # --- CreateRole trusted by this account, allowed to tag sessions and to use one bucket.
    role_name = ctx.unique_name("sim2real-behav-role-")
    bucket = ctx.unique_name("sim2real-behav-sts-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }],
    }
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, role_name))
    role_arn = created["Arn"]
    assert role_arn == f"arn:{partition}:iam::{account}:role/{role_name}", role_arn
    role_id = iam.get_role(RoleName=role_name)["Role"]["RoleId"]
    assert role_id == created["RoleId"], (
        f"GetRole RoleId {role_id!r} differs from CreateRole's {created['RoleId']!r}"
    )
    permissions = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:CreateBucket", "s3:PutObject"],
            "Resource": [f"arn:{partition}:s3:::{bucket}", f"arn:{partition}:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-bucket",
                        PolicyDocument=json.dumps(permissions))
    ctx.on_cleanup(lambda: _delete_role_policy_if_exists(iam, role_name, "sim2real-bucket"))

    # --- AssumeRole with a duration and a session tag (IAM trust is eventually consistent).
    session = ctx.unique_name("sess-")
    assumed = _poll(
        lambda: _try_assume(sts, RoleArn=role_arn, RoleSessionName=session,
                            DurationSeconds=_DURATION_S,
                            Tags=[{"Key": _TAG_KEY, "Value": _TAG_VALUE}]),
        lambda r: r is not None, timeout_s=90, interval_s=3, what="the new role becomes assumable",
    )
    creds = assumed["Credentials"]
    _assert_temporary_credentials(creds, "AssumeRole")
    expected_arn = f"arn:{partition}:sts::{account}:assumed-role/{role_name}/{session}"
    expected_user_id = f"{role_id}:{session}"
    user = assumed["AssumedRoleUser"]
    assert user["Arn"] == expected_arn, (
        f"AssumedRoleUser.Arn {user['Arn']!r}, expected {expected_arn!r}"
    )
    assert user["AssumedRoleId"] == expected_user_id, (
        f"AssumedRoleUser.AssumedRoleId {user['AssumedRoleId']!r}, expected <RoleId>:<session> "
        f"{expected_user_id!r}"
    )

    # --- The temporary credentials sign real calls against the same target.
    temp_sts = _client_from(ctx, "sts", creds)
    temp_s3 = _client_from(ctx, "s3", creds)
    ident = temp_sts.get_caller_identity()
    assert ident["Arn"] == expected_arn, f"session GetCallerIdentity Arn {ident['Arn']!r}"
    assert ident["UserId"] == expected_user_id, f"session GetCallerIdentity UserId {ident['UserId']!r}"
    assert ident["Account"] == account, f"session GetCallerIdentity Account {ident['Account']!r}"

    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    # An inline role policy is eventually consistent for a session already issued.
    _poll(lambda: _try_s3(temp_s3.create_bucket, **create_kwargs), lambda ok: ok,
          timeout_s=90, interval_s=3, what="the session can create its bucket")
    ctx.on_cleanup(lambda: _delete_bucket_if_exists(s3, bucket))
    put = temp_s3.put_object(Bucket=bucket, Key="journey.txt", Body=_BODY)
    assert put["ETag"], "PutObject with session credentials returned no ETag"
    got = s3.get_object(Bucket=bucket, Key="journey.txt")["Body"].read()
    assert got == _BODY, (
        f"the object written with session credentials reads back {len(got)} bytes with the base "
        f"credentials, expected the {len(_BODY)} bytes written"
    )
    s3.delete_object(Bucket=bucket, Key="journey.txt")
    s3.delete_bucket(Bucket=bucket)
    code, msg, status = _poll(lambda: _head_bucket_error(s3, bucket), lambda r: r != _SUCCEEDED,
                              timeout_s=30, interval_s=2, what="the deleted bucket is gone")
    # A HEAD refusal has no body: the SDK reads the status as the code and its reason as the message.
    assert (code, msg) == ("404", "Not Found") and status == 404, (
        f"HeadBucket on the deleted bucket answered {code!r}/{msg!r} HTTP {status!r}, expected 404 Not Found"
    )

    # --- GetSessionToken with the base credentials: usable temporary credentials, same principal.
    token = sts.get_session_token(DurationSeconds=_DURATION_S)["Credentials"]
    _assert_temporary_credentials(token, "GetSessionToken")
    token_ident = _client_from(ctx, "sts", token).get_caller_identity()
    assert (token_ident["Arn"], token_ident["UserId"], token_ident["Account"]) == (
        base_identity["Arn"], base_identity["UserId"], base_identity["Account"]
    ), f"GetSessionToken credentials resolve to {token_ident!r}, expected {base_identity!r}"

    # --- Delete the role: it is gone, and a new AssumeRole on it is refused.
    iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-bucket")
    iam.delete_role(RoleName=role_name)
    gone = _poll(lambda: _get_role_error(iam, role_name), lambda r: r != _SUCCEEDED,
                 timeout_s=30, interval_s=2, what="GetRole refuses the deleted role")
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    assert gone[:2] == role_gone and 400 <= (gone[2] or 0) < 500, (
        f"GetRole on the deleted role answered {gone!r}, expected {role_gone} and 4xx"
    )
    code, message, status = _poll(
        lambda: _assume_outcome(sts, role_arn, ctx.unique_name("sess2-")),
        # Bounded well inside a 60 s first pass, so a target that never revokes fails here.
        lambda r: r != _SUCCEEDED, timeout_s=35, interval_s=2,
        what="AssumeRole on the deleted role is refused",
    )
    denied = (
        "AccessDenied",
        f"User: {base_identity['Arn']} is not authorized to perform: sts:AssumeRole on resource: {role_arn}",
    )
    assert (code, message) == denied, f"AssumeRole on a deleted role answered {(code, message)!r}, expected {denied}"
    assert isinstance(status, int) and 400 <= status < 500, f"refusal was HTTP {status!r}, not 4xx"

    # --- The session issued before the deletion still resolves.
    after = temp_sts.get_caller_identity()
    assert (after["Arn"], after["UserId"], after["Account"]) == (
        expected_arn, expected_user_id, account
    ), f"the issued session resolves to {after!r} after the role was deleted"


def _assert_temporary_credentials(creds, op) -> None:
    # The key-id prefix is an AWS encoding detail no client reads; only its presence is graded.
    assert len(creds.get("AccessKeyId") or "") >= 16, f"{op} returned no usable AccessKeyId"
    assert creds.get("SecretAccessKey"), f"{op} returned an empty SecretAccessKey"
    assert creds.get("SessionToken"), f"{op} returned an empty SessionToken"
    expiration = creds["Expiration"]
    if isinstance(expiration, str):
        expiration = _dt.datetime.fromisoformat(expiration.replace("Z", "+00:00"))
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=_dt.timezone.utc)
    remaining = (expiration - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    assert abs(remaining - _DURATION_S) <= _EXPIRY_SLACK_S, (
        f"{op} Expiration is {remaining:.0f}s from now, expected {_DURATION_S}s "
        f"+/- {_EXPIRY_SLACK_S}s"
    )


def _client_from(ctx, service, creds):
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _poll(probe, done, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if done(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")


def _try_assume(sts, **kwargs):
    """AssumeRole's response, or None while the new trust is still propagating (AccessDenied)."""
    try:
        return sts.assume_role(**kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return None
        raise


def _try_s3(call, **kwargs) -> bool:
    """True once the call succeeds; False while the session's new policy is propagating."""
    try:
        call(**kwargs)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return False
        raise


def _assume_outcome(sts, role_arn, session):
    """(code, message, HTTP status) once AssumeRole is refused; _SUCCEEDED while it succeeds."""
    try:
        sts.assume_role(RoleArn=role_arn, RoleSessionName=session)
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message"), e.response["ResponseMetadata"].get("HTTPStatusCode")
    return _SUCCEEDED


def _get_role_error(iam, role_name):
    """(code, message, HTTP status) of GetRole's error, or _SUCCEEDED while the role reads back."""
    try:
        iam.get_role(RoleName=role_name)
        return _SUCCEEDED
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message"), e.response["ResponseMetadata"].get("HTTPStatusCode")


def _head_bucket_error(s3, bucket):
    """(code, message, HTTP status) of HeadBucket's error, or _SUCCEEDED while the bucket exists."""
    try:
        s3.head_bucket(Bucket=bucket)
        return _SUCCEEDED
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message"), e.response["ResponseMetadata"].get("HTTPStatusCode")


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
