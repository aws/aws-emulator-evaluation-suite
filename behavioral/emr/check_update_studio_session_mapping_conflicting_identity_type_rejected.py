"""update-studio-session-mapping-conflicting-identity-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-studio-session-mapping-conflicting-identity-type-rejected"
GROUP = "negative-classes"
SERVICES = ["emr"]

_POLICY_A = "arn:aws:iam::aws:policy/ReadOnlyAccess"
_POLICY_B = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateStudioSessionMapping with the mapping's IdentityId but the wrong IdentityType is rejected as
    no existing mapping, since the key is (StudioId, IdentityType, IdentityId), while the update under
    the correct type still succeeds.
    """
    emr = ctx.client("emr")

    idc_arn, identity_store_id = _sso_instance(ctx)
    studio_id = _create_sso_studio(ctx, idc_arn)
    group_id = _create_identity_store_group(ctx, identity_store_id)

    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id, SessionPolicyArn=_POLICY_A
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(
            StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id
        )
    )

    # Positive control: updating under the correct (original) IdentityType succeeds.
    emr.update_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id, SessionPolicyArn=_POLICY_B
    )
    mapping = emr.get_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id
    )["SessionMapping"]
    assert mapping["SessionPolicyArn"] == _POLICY_B, (
        f"expected the correctly-typed update to have persisted {_POLICY_B!r}, "
        f"got {mapping['SessionPolicyArn']!r}"
    )

    # Negative: same StudioId + IdentityId, but IdentityType now conflicts with the type
    # the mapping was actually created under.
    code, message = _error(
        lambda: emr.update_studio_session_mapping(
            StudioId=studio_id, IdentityType="USER", IdentityId=group_id, SessionPolicyArn=_POLICY_A
        )
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for an UpdateStudioSessionMapping call whose "
        f"IdentityType conflicts with the mapping's real type, got {code!r}"
    )
    expected = _service_message("IdentityId is invalid.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    # Effect absent: the GROUP mapping is untouched by the rejected USER-typed update, and
    # no USER mapping for this identity was ever created.
    mapping_after = emr.get_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id
    )["SessionMapping"]
    assert mapping_after["SessionPolicyArn"] == _POLICY_B, (
        f"the rejected USER-typed update must not have touched the GROUP mapping: "
        f"expected {_POLICY_B!r}, got {mapping_after['SessionPolicyArn']!r}"
    )

    user_lookup_code, user_lookup_message = _error(
        lambda: emr.get_studio_session_mapping(
            StudioId=studio_id, IdentityType="USER", IdentityId=group_id
        )
    )
    assert user_lookup_code == "InvalidRequestException", (
        f"expected no USER mapping to exist for this identity id "
        f"(GetStudioSessionMapping should raise InvalidRequestException), got {user_lookup_code!r}"
    )
    expected = _service_message("IdentityId is invalid.", user_lookup_message)
    assert user_lookup_message == expected, f"expected the message {expected!r}, got {user_lookup_message!r}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry(fn, attempts: int = 6, delay_s: float = 3.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _sso_instance(ctx):
    """The account's IAM Identity Center instance, created if the account has none.

    sso-admin CreateInstance provisions a standalone account instance, so the prerequisite is met
    in-check. It is an account-wide singleton other checks in the account use, so one created here
    is kept, like the run's shared network.
    """
    sso = ctx.client("sso-admin")
    if not sso.list_instances().get("Instances", []):
        sso.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    deadline = time.monotonic() + 120
    while True:
        found = sso.list_instances().get("Instances", [])
        failed = [i for i in found if i.get("Status") == "CREATE_FAILED"]
        if failed:
            raise AssertionError(f"IAM Identity Center instance creation failed: {failed}")
        active = [i for i in found if i.get("Status") == "ACTIVE" and "IdentityStoreId" in i]
        if active:
            return active[0]["InstanceArn"], active[0]["IdentityStoreId"]
        if time.monotonic() >= deadline:
            raise AssertionError("IAM Identity Center instance did not become ACTIVE within 120s")
        time.sleep(3)


def _delete_security_group(ec2, sg_id, timeout_s=300.0):
    """Delete a security group, retrying while the deleted studio's network interfaces hold it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _empty_and_delete_bucket(s3, bucket):
    """Empty the bucket (whatever the studio wrote under its DefaultS3Location), then delete it."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        victims = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if victims:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for an EMR Studio")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for an EMR Studio")
    return vpc_id, [s["SubnetId"] for s in subnets[:2]]


def _create_studio_security_groups(ctx, vpc_id: str):
    ec2 = ctx.client("ec2")
    workspace_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"),
        Description="sim2real emr studio workspace sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group(ec2, workspace_sg))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-en-"),
        Description="sim2real emr studio engine sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group(ec2, engine_sg))
    return workspace_sg, engine_sg


def _create_studio_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # EMR Studio's service role must be able to read/write the DefaultS3Location bucket
    # and manage the Workspace<->cluster network channel, or CreateStudio itself rejects
    # the role up front.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:GetEncryptionConfiguration",
                    "s3:ListBucket",
                    "s3:DeleteObject",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:CreateNetworkInterface",
                    "ec2:CreateNetworkInterfacePermission",
                    "ec2:DeleteNetworkInterface",
                    "ec2:DeleteNetworkInterfacePermission",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:ModifyNetworkInterfaceAttribute",
                    "ec2:AuthorizeSecurityGroupEgress",
                    "ec2:AuthorizeSecurityGroupIngress",
                    "ec2:CreateSecurityGroup",
                    "ec2:DescribeSecurityGroups",
                    "ec2:RevokeSecurityGroupEgress",
                    "ec2:DescribeTags",
                    "ec2:DescribeInstances",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeVpcs",
                    "ec2:CreateTags",
                    "elasticmapreduce:ListInstances",
                    "elasticmapreduce:DescribeCluster",
                    "elasticmapreduce:ListSteps",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "iam:GetUser",
                    "iam:GetRole",
                    "iam:ListUsers",
                    "iam:ListRoles",
                    "sso:GetManagedApplicationInstance",
                    "sso-directory:SearchUsers",
                    "sso:DescribeApplication",
                    "sso:DescribeInstance",
                ],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-emr-studio-inline",
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-emr-studio-inline")
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_studio_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-studio-").lower().strip("-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return f"s3://{bucket}/"


def _create_sso_studio(ctx, idc_instance_arn: str) -> str:
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    workspace_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id)
    role_arn = _create_studio_service_role(ctx)
    s3_location = _create_studio_bucket(ctx)
    emr = ctx.client("emr")

    def _create():
        return emr.create_studio(
            Name=ctx.unique_name("sim2real-emr-studio-"),
            AuthMode="SSO",
            VpcId=vpc_id,
            SubnetIds=subnet_ids,
            ServiceRole=role_arn,
            WorkspaceSecurityGroupId=workspace_sg,
            EngineSecurityGroupId=engine_sg,
            DefaultS3Location=s3_location,
            IdcInstanceArn=idc_instance_arn,
            # An SSO studio needs a UserRole ("UserRole is required to create a studio with SSO
            # auth-mode"); assignment OPTIONAL keeps identities mappable without assignment.
            UserRole=role_arn,
            IdcUserAssignment="OPTIONAL",
            Tags=_TAGS,
        )

    try:
        resp = _retry(_create, attempts=18, delay_s=5.0)  # IAM role propagation to EMR
    except ClientError as exc:
        raise AssertionError(
            f"CreateStudio(AuthMode=SSO) failed in this account/region: "
            f"{exc.response['Error']['Code']}"
        ) from exc
    studio_id = resp["StudioId"]
    ctx.on_cleanup(lambda: emr.delete_studio(StudioId=studio_id))
    return studio_id


def _create_identity_store_group(ctx, identity_store_id: str) -> str:
    idstore = ctx.client("identitystore")
    resp = idstore.create_group(
        IdentityStoreId=identity_store_id, DisplayName=ctx.unique_name("sim2real-emr-grp-")
    )
    group_id = resp["GroupId"]
    ctx.on_cleanup(
        lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    )
    return group_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
