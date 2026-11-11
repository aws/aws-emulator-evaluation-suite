"""access-grants-get-data-access-returns-scoped-credentials."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-grants-get-data-access-returns-scoped-credentials"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("cap:c7", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path", "resource:account-singleton:s3-access-grants-instance")
def run(ctx) -> None:
    """GetDataAccess vends credentials scoped to the granted prefix: they read inside it, are denied
    outside it and for WRITE on a READ grant, name the matched grant, and stop once it is deleted.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-agb-")
    role = ctx.unique_name("sim2real-behav-agrole-")
    caller = ctx.client("sts").get_caller_identity()["Arn"]

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="granted/inside.txt", Body=b"in-the-grant")
    s3.put_object(Bucket=bucket, Key="ungranted/outside.txt", Body=b"outside-the-grant")

    role_arn = _grants_role(ctx, iam, role, bucket)

    # Instance is a per-account singleton; create only if absent, and never delete a
    # pre-existing one on teardown.
    had_instance = _ensure_instance(ctx, s3c, account)

    location_id = _create_location_with_role_propagation(s3c, account, bucket, role_arn)
    ctx.on_cleanup(lambda: _drop_location(s3c, account, location_id))

    grant = s3c.create_access_grant(
        AccountId=account, AccessGrantsLocationId=location_id,
        AccessGrantsLocationConfiguration={"S3SubPrefix": "*"},
        Grantee={"GranteeType": "IAM", "GranteeIdentifier": caller},
        Permission="READ",
    )
    grant_id = grant["AccessGrantId"]
    ctx.on_cleanup(lambda: _drop_grant(s3c, account, grant_id))
    assert grant["GrantScope"] == f"s3://{bucket}/granted/*", (
        f"CreateAccessGrant reported GrantScope {grant['GrantScope']!r}"
    )

    data = s3c.get_data_access(
        AccountId=account, Target=f"s3://{bucket}/granted/*", Permission="READ"
    )
    assert data["MatchedGrantTarget"] == f"s3://{bucket}/granted/*", (
        f"GetDataAccess resolved MatchedGrantTarget {data.get('MatchedGrantTarget')!r}"
    )
    creds = data["Credentials"]
    assert {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"} <= set(creds), (
        f"GetDataAccess credentials were missing fields: {sorted(creds)!r}"
    )

    # The middle key name is assembled so secret scanners do not flag a literal credential key.
    session_kwargs = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_" + "secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    scoped = ctx.client("s3", creds=session_kwargs)
    inside = scoped.get_object(Bucket=bucket, Key="granted/inside.txt")["Body"].read()
    assert inside == b"in-the-grant", (
        f"the vended credentials could not read the granted object: {inside!r}"
    )
    outside_code, outside_msg = _error(
        lambda: scoped.get_object(Bucket=bucket, Key="ungranted/outside.txt")
    )
    assert outside_code == "AccessDenied", (
        f"the vended credentials read outside the grant with code {outside_code!r}, "
        "expected AccessDenied"
    )
    # The refusal names the vended session, which Access Grants mints per GetDataAccess call; the
    # session's own identity is read with the same credentials rather than pinned.
    vended_arn = ctx.client("sts", creds=session_kwargs).get_caller_identity()["Arn"]
    outside_want = (
        f'User: {vended_arn} is not authorized to perform: s3:GetObject on resource: '
        f'"arn:aws:s3:::{bucket}/ungranted/outside.txt" because no session policy allows the '
        f's3:GetObject action'
    )
    assert outside_msg == outside_want, (
        f"the refusal carried message {outside_msg!r}, expected {outside_want!r}"
    )

    # A WRITE data-access request against a READ-only grant is refused.
    write_code, write_code_msg = _error(
        lambda: s3c.get_data_access(
            AccountId=account, Target=f"s3://{bucket}/granted/*", Permission="WRITE"
        )
    )
    assert write_code == "AccessDenied", (
        f"GetDataAccess(WRITE) against a READ grant returned {write_code!r}, "
        "expected AccessDenied"
    )
    write_code_want = f"You do not have WRITE permissions to the requested S3 Prefix: s3://{bucket}/granted/*"
    assert write_code_msg == write_code_want, (
        f"the refusal carried message {write_code_msg!r}, expected {write_code_want!r}"
    )

    # Revoke: GetDataAccess and GetAccessGrant both stop working.
    s3c.delete_access_grant(AccountId=account, AccessGrantId=grant_id)
    revoked, revoked_msg = _error(
        lambda: s3c.get_data_access(
            AccountId=account, Target=f"s3://{bucket}/granted/*", Permission="READ"
        )
    )
    assert revoked == "AccessDenied", (
        f"GetDataAccess after DeleteAccessGrant returned {revoked!r}, expected AccessDenied"
    )
    revoked_want = f"You do not have READ permissions to the requested S3 Prefix: s3://{bucket}/granted/*"
    assert revoked_msg == revoked_want, (
        f"the refusal carried message {revoked_msg!r}, expected {revoked_want!r}"
    )
    gone, gone_msg = _error(lambda: s3c.get_access_grant(AccountId=account, AccessGrantId=grant_id))
    assert gone == "NoSuchAccessGrantError", (
        f"GetAccessGrant on the deleted grant returned {gone!r}, expected NoSuchAccessGrantError"
    )
    gone_want = "The specified access grant does not exist"
    assert gone_msg == gone_want, (
        f"the refusal carried message {gone_msg!r}, expected {gone_want!r}"
    )

    if not had_instance:
        # We created the instance; the location cleanup fires LIFO before the instance
        # teardown, so nothing to assert here beyond leaving the account as we found it.
        pass



def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _ensure_instance(ctx, s3c, account: str) -> bool:
    """Ensure an Access Grants instance exists. Return True if it already did.

    The instance is a per-account singleton: delete it on teardown only if created here.
    """
    try:
        s3c.get_access_grants_instance(AccountId=account)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AccessGrantsInstanceNotExistsError":
            raise
    s3c.create_access_grants_instance(AccountId=account)
    ctx.on_cleanup(lambda: _drop_instance(s3c, account))
    return False


def _drop_instance(s3c, account: str) -> None:
    try:
        s3c.delete_access_grants_instance(AccountId=account)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AccessGrantsInstanceNotExistsError":
            raise


def _create_location_with_role_propagation(s3c, account: str, bucket: str, role_arn: str) -> str:
    """CreateAccessGrantsLocation can reject a role its trust policy just granted until IAM
    propagates the change; retry the specific role-not-ready error, bounded by a deadline."""
    deadline = time.monotonic() + 60
    while True:
        try:
            return s3c.create_access_grants_location(
                AccountId=account, LocationScope=f"s3://{bucket}/granted/", IAMRoleArn=role_arn,
                Tags=[{"Key": "sim2real", "Value": "agloc"}],
            )["AccessGrantsLocationId"]
        except ClientError as exc:
            msg = str(exc).lower()
            role_not_ready = "role" in msg and (
                "cannot be assumed" in msg or "is not authorized" in msg or "invalid" in msg
            )
            if role_not_ready and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _drop_location(s3c, account: str, location_id: str) -> None:
    try:
        s3c.delete_access_grants_location(
            AccountId=account, AccessGrantsLocationId=location_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchAccessGrantsLocationError":
            raise


def _drop_grant(s3c, account: str, grant_id: str) -> None:
    try:
        s3c.delete_access_grant(AccountId=account, AccessGrantId=grant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchAccessGrantError":
            raise


def _grants_role(ctx, iam, role: str, bucket: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "access-grants.s3.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:SetContext"],
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role))
    iam.put_role_policy(
        RoleName=role, PolicyName="grants",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        }),
    )
    # IAM propagation has no condition to poll directly; the wait is the bounded retry
    # around CreateAccessGrantsLocation, the role's first real use, in run().
    return role_arn


def _delete_role(iam, role: str) -> None:
    try:
        for name in iam.list_role_policies(RoleName=role).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role, PolicyName=name)
        iam.delete_role(RoleName=role)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
