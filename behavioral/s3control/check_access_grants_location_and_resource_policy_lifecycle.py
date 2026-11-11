"""access-grants-location-and-resource-policy-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-grants-location-and-resource-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags(
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
    "axis:happy-path",
    "resource:account-singleton:s3-access-grants-instance",
)
def run(ctx) -> None:
    """DeleteAccessGrantsLocation is refused while a grant references the location and succeeds after;
    UpdateAccessGrantsLocation swaps the role in place; the instance resource policy round-trips
    through Put/Get and Delete leaves a NotExists 404.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-agl-")
    role = ctx.unique_name("sim2real-behav-aglrole-")
    role2 = ctx.unique_name("sim2real-behav-aglrole2-")
    caller = ctx.client("sts").get_caller_identity()["Arn"]

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    role_arn = _grants_role(ctx, iam, role, bucket)
    role_arn2 = _grants_role(ctx, iam, role2, bucket)
    _ensure_instance(ctx, s3c, account)

    # The instance and the just-created IAM role are both eventually consistent from S3
    # Control's perspective; retry the first real use of each, bounded, instead of a fixed wait.
    location_id = _retry_transient(
        lambda: s3c.create_access_grants_location(
            AccountId=account, LocationScope=f"s3://{bucket}/data/", IAMRoleArn=role_arn,
            Tags=[{"Key": "sim2real", "Value": "agloc"}],
        )
    )["AccessGrantsLocationId"]
    ctx.on_cleanup(lambda: _drop_location(s3c, account, location_id))

    got = s3c.get_access_grants_location(
        AccountId=account, AccessGrantsLocationId=location_id
    )
    assert got["LocationScope"] == f"s3://{bucket}/data/", (
        f"GetAccessGrantsLocation reported LocationScope {got['LocationScope']!r}"
    )
    assert got["IAMRoleArn"] == role_arn, (
        f"GetAccessGrantsLocation reported IAMRoleArn {got['IAMRoleArn']!r}"
    )

    # UpdateAccessGrantsLocation swaps the role in place. role_arn2 was just created too, so
    # the same propagation retry applies.
    _retry_transient(lambda: s3c.update_access_grants_location(
        AccountId=account, AccessGrantsLocationId=location_id, IAMRoleArn=role_arn2
    ))
    after = s3c.get_access_grants_location(
        AccountId=account, AccessGrantsLocationId=location_id
    )
    assert after["IAMRoleArn"] == role_arn2, (
        f"UpdateAccessGrantsLocation left IAMRoleArn {after['IAMRoleArn']!r}, expected the "
        "second role"
    )
    assert after["AccessGrantsLocationId"] == location_id, (
        "the update re-minted the location id"
    )

    grant_id = s3c.create_access_grant(
        AccountId=account, AccessGrantsLocationId=location_id,
        AccessGrantsLocationConfiguration={"S3SubPrefix": "*"},
        Grantee={"GranteeType": "IAM", "GranteeIdentifier": caller},
        Permission="READ",
    )["AccessGrantId"]
    ctx.on_cleanup(lambda: _drop_grant(s3c, account, grant_id))

    # Referential integrity: the location cannot be dropped while the grant references it.
    code, code_msg = _error(
        lambda: s3c.delete_access_grants_location(
            AccountId=account, AccessGrantsLocationId=location_id
        )
    )
    assert code == "AccessGrantsLocationNotEmptyError", (
        f"deleting an in-use location returned {code!r}, "
        "expected AccessGrantsLocationNotEmptyError"
    )
    code_want = "Please delete access grants before deleting access grants location"
    assert code_msg == code_want, (
        f"the refusal carried message {code_msg!r}, expected {code_want!r}"
    )
    # Effect absent: the location is still there.
    assert s3c.get_access_grants_location(
        AccountId=account, AccessGrantsLocationId=location_id
    )["AccessGrantsLocationId"] == location_id, (
        "the refused delete removed the location anyway"
    )

    # Instance resource policy is a separate round-tripping record.
    resource_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": ["s3:ListAccessGrants"],
                "Resource": f"arn:aws:s3:{ctx.region}:{account}:access-grants/default",
            }
        ],
    }
    s3c.put_access_grants_instance_resource_policy(
        AccountId=account, Policy=json.dumps(resource_policy)
    )
    ctx.on_cleanup(lambda: _drop_resource_policy(s3c, account))
    stored = json.loads(
        s3c.get_access_grants_instance_resource_policy(AccountId=account)["Policy"]
    )
    stored_action = stored["Statement"][0]["Action"]
    # IAM normalises a single-element Action list to a bare string; accept either form.
    assert stored_action in ("s3:ListAccessGrants", ["s3:ListAccessGrants"]), (
        f"the instance resource policy read back with Action {stored_action!r}"
    )
    s3c.delete_access_grants_instance_resource_policy(AccountId=account)
    gone, gone_msg = _error(
        lambda: s3c.get_access_grants_instance_resource_policy(AccountId=account)
    )
    assert gone == "AccessGrantsInstanceResourcePolicyNotExists", (
        f"the resource policy survived its delete: Get returned {gone!r}"
    )
    gone_want = "Access Grants Instance Resource Policy does not exist"
    assert gone_msg == gone_want, (
        f"the refusal carried message {gone_msg!r}, expected {gone_want!r}"
    )

    # Now that the grant is gone, the location deletes cleanly — proving the earlier refusal
    # was about the reference, not a permanent lock.
    s3c.delete_access_grant(AccountId=account, AccessGrantId=grant_id)
    grant_gone, grant_gone_msg = _error(
        lambda: s3c.get_access_grant(AccountId=account, AccessGrantId=grant_id)
    )
    assert grant_gone == "NoSuchAccessGrantError", (
        f"GetAccessGrant after DeleteAccessGrant returned {grant_gone!r}, "
        "expected NoSuchAccessGrantError"
    )
    grant_gone_want = "The specified access grant does not exist"
    assert grant_gone_msg == grant_gone_want, (
        f"the refusal carried message {grant_gone_msg!r}, expected {grant_gone_want!r}"
    )

    s3c.delete_access_grants_location(AccountId=account, AccessGrantsLocationId=location_id)
    missing, missing_msg = _error(
        lambda: s3c.get_access_grants_location(
            AccountId=account, AccessGrantsLocationId=location_id
        )
    )
    assert missing == "NoSuchAccessGrantsLocationError", (
        f"GetAccessGrantsLocation after the delete returned {missing!r}, "
        "expected NoSuchAccessGrantsLocationError"
    )
    missing_want = "The specified access grants location does not exist"
    assert missing_msg == missing_want, (
        f"the refusal carried message {missing_msg!r}, expected {missing_want!r}"
    )
    # The dead id is not just unreadable — it is unusable: a mutation against it fails too.
    dead_update, dead_update_msg = _error(
        lambda: s3c.update_access_grants_location(
            AccountId=account, AccessGrantsLocationId=location_id, IAMRoleArn=role_arn
        )
    )
    assert dead_update == "NoSuchAccessGrantsLocationError", (
        f"UpdateAccessGrantsLocation on the deleted location returned {dead_update!r}, "
        "expected NoSuchAccessGrantsLocationError"
    )
    dead_update_want = "The specified access grants location does not exist"
    assert dead_update_msg == dead_update_want, (
        f"the refusal carried message {dead_update_msg!r}, expected {dead_update_want!r}"
    )



def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _retry_transient(fn, deadline_s: float = 30.0, interval_s: float = 3.0):
    """Retry ``fn`` while S3 Control has not yet caught up with IAM/instance propagation.

    Bounded so a genuinely bad request still fails — just after the deadline instead of on
    the first attempt.
    """
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _ensure_instance(ctx, s3c, account: str) -> bool:
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


def _drop_resource_policy(s3c, account: str) -> None:
    try:
        s3c.delete_access_grants_instance_resource_policy(AccountId=account)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("AccessGrantsInstanceResourcePolicyNotExists", "AccessGrantsInstanceNotExistsError"):
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
