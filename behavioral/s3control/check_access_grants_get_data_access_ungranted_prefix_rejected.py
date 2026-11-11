"""access-grants-get-data-access-ungranted-prefix-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-grants-get-data-access-ungranted-prefix-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:s3-access-grants-instance")
def run(ctx) -> None:
    """GetDataAccess vends credentials for a prefix inside a grant but refuses, without credentials,
    a sibling prefix under the same location that no grant covers.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-agn-")
    role = ctx.unique_name("sim2real-behav-agnrole-")
    caller = ctx.client("sts").get_caller_identity()["Arn"]

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="team-a/file.txt", Body=b"granted")
    s3.put_object(Bucket=bucket, Key="team-b/file.txt", Body=b"ungranted")

    role_arn = _grants_role(ctx, iam, role, bucket)
    had_instance = _ensure_instance(ctx, s3c, account)

    # The location spans the whole bucket, but the grant only covers team-a/. Both the IAM
    # role's trust policy and (if just created) the instance are eventually consistent with no
    # separate condition to poll, so retry the operation that actually needs them settled
    # instead of guessing a fixed sleep.
    location_id = _retry_on_propagation(
        60.0,
        lambda: s3c.create_access_grants_location(
            AccountId=account, LocationScope=f"s3://{bucket}/", IAMRoleArn=role_arn,
            Tags=[{"Key": "sim2real", "Value": "agloc"}],
        ),
    )["AccessGrantsLocationId"]
    ctx.on_cleanup(lambda: _drop_location(s3c, account, location_id))
    grant_id = s3c.create_access_grant(
        AccountId=account, AccessGrantsLocationId=location_id,
        AccessGrantsLocationConfiguration={"S3SubPrefix": "team-a/*"},
        Grantee={"GranteeType": "IAM", "GranteeIdentifier": caller},
        Permission="READ",
    )["AccessGrantId"]
    ctx.on_cleanup(lambda: _drop_grant(s3c, account, grant_id))

    # Positive control: the granted prefix vends. GetDataAccess assumes the location's role,
    # so it shares the same IAM-propagation window as the location create above.
    granted = _retry_on_propagation(
        30.0,
        lambda: s3c.get_data_access(
            AccountId=account, Target=f"s3://{bucket}/team-a/*", Permission="READ"
        ),
    )
    assert "Credentials" in granted and granted["Credentials"].get("AccessKeyId"), (
        f"GetDataAccess for the granted prefix returned {granted!r} without credentials"
    )

    # The sibling prefix under the SAME location has no grant.
    try:
        refused = s3c.get_data_access(
            AccountId=account, Target=f"s3://{bucket}/team-b/*", Permission="READ"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "AccessDenied", (
            f"GetDataAccess for the ungranted prefix returned {code!r}, expected AccessDenied"
        )
        message = exc.response["Error"].get("Message")
        want = f"You do not have READ permissions to the requested S3 Prefix: s3://{bucket}/team-b/*"
        assert message == want, (
            f"the refusal carried message {message!r}, expected {want!r}"
        )
    else:
        raise AssertionError(
            "GetDataAccess vended credentials for an ungranted prefix: "
            f"{ {k: v for k, v in refused.items() if k != 'Credentials'} !r}"
        )



def _retry_on_propagation(deadline_s: float, fn):
    """Retry ``fn`` while IAM trust-policy / instance-visibility propagation settles.

    Neither has an observable condition to poll, so the propagation-sensitive call itself is
    retried against a deadline; the last ClientError is re-raised once it elapses.
    """
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)


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
