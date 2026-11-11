"""studio-session-mapping-unicode-identity-name-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "studio-session-mapping-unicode-identity-name-preserved"
GROUP = "representation"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A studio session mapping created with a unicode identity display name round-trips byte-identical."""
    idc_arn, identity_store_id = _identity_center_instance(ctx)

    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    ws_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id)
    service_role_arn = _ensure_studio_service_role(ctx)
    bucket = _create_bucket(ctx)
    session_policy_arn = _create_session_policy(ctx)

    identitystore = ctx.client("identitystore")
    unicode_name = ctx.unique_name("sim2real-\u65e5\u672c\u8a9e-\U0001f680-")
    group_id = identitystore.create_group(IdentityStoreId=identity_store_id, DisplayName=unicode_name)["GroupId"]
    ctx.on_cleanup(lambda: _delete_group_safe(ctx, identity_store_id, group_id))

    emr = ctx.client("emr")
    studio_id = _create_studio_with_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-studio-"),
        AuthMode="SSO",
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        ServiceRole=service_role_arn,
        WorkspaceSecurityGroupId=ws_sg,
        EngineSecurityGroupId=engine_sg,
        DefaultS3Location=f"s3://{bucket}/studio/",
        IdcInstanceArn=idc_arn,
        # An SSO studio needs a UserRole ("UserRole is required to create a studio with SSO
        # auth-mode"); assignment OPTIONAL keeps users and groups mappable without assignment.
        UserRole=service_role_arn,
        IdcUserAssignment="OPTIONAL",
    )["StudioId"]
    ctx.on_cleanup(lambda: _delete_studio_safe(ctx, studio_id))

    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityName=unicode_name, SessionPolicyArn=session_policy_arn
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityName=unicode_name)
    )

    mapping = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityName=unicode_name)[
        "SessionMapping"
    ]
    assert mapping["IdentityName"] == unicode_name, (
        f"expected IdentityName {unicode_name!r} preserved byte-identical, got {mapping['IdentityName']!r}"
    )
    assert len(mapping["IdentityName"]) == len(unicode_name), (
        f"expected IdentityName length {len(unicode_name)}, got {len(mapping['IdentityName'])} "
        f"(value {mapping['IdentityName']!r})"
    )

    # Fetch again by IdentityId to confirm the name is not merely echoed back verbatim from the
    # request but genuinely persisted server-side.
    mapping_by_id = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id)[
        "SessionMapping"
    ]
    assert mapping_by_id["IdentityName"] == unicode_name, (
        f"expected IdentityName {unicode_name!r} when read back by IdentityId {group_id!r}, "
        f"got {mapping_by_id['IdentityName']!r}"
    )
    assert mapping_by_id["IdentityId"] == group_id, (
        f"expected IdentityId {group_id!r} echoed on the by-id read, got {mapping_by_id['IdentityId']!r}"
    )


# ===== helpers =====

def _identity_center_instances(ctx):
    """The account's IAM Identity Center instances, creating one if the account has none.

    `sso-admin:CreateInstance` provisions a STANDALONE (non-Organizations) instance, so the
    prerequisite is satisfiable in-check and an account without an instance does not block the
    check. Exactly one instance is allowed per account and deleting it would disrupt any other
    check relying on it, so one created here is deliberately never torn down.
    """
    import time

    from botocore.exceptions import ClientError

    sso_idc = ctx.client("sso-admin")
    try:
        instances = sso_idc.list_instances().get("Instances", [])
    except ClientError as exc:
        raise AssertionError(
            f"cannot query IAM Identity Center instances ({exc.response['Error']['Code']})"
        ) from exc
    if not instances:
        sso_idc.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    deadline = time.time() + 120
    while time.time() < deadline:
        found = sso_idc.list_instances().get("Instances", [])
        for inst in found:
            if inst.get("Status") == "CREATE_FAILED":
                raise AssertionError(f"IAM Identity Center instance creation failed: {inst}")
        if any(i.get("Status") == "ACTIVE" and "IdentityStoreId" in i for i in found):
            return found
        time.sleep(3)
    raise AssertionError(
        "IAM Identity Center instance did not become ACTIVE with an IdentityStoreId within 120s"
    )



def _identity_center_instance(ctx) -> tuple[str, str]:
    instances = _identity_center_instances(ctx)
    inst = instances[0]
    return inst["InstanceArn"], inst["IdentityStoreId"]


def _tolerating(fn, *gone_codes) -> None:
    """A teardown call; only the listed already-gone error codes are tolerated."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in gone_codes:
            raise


def _delete_group_safe(ctx, identity_store_id: str, group_id: str) -> None:
    identitystore = ctx.client("identitystore")
    _tolerating(lambda: identitystore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id),
                "ResourceNotFoundException")


def _default_vpc_and_subnet(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to place an EMR Studio into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no subnets to place an EMR Studio into")
    return vpc_id, subnets[0]["SubnetId"]


def _create_studio_security_groups(ctx, vpc_id: str) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-ws-"),
        Description="sim2real EMR studio workspace sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_safe(ctx, ws_sg))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-eng-"),
        Description="sim2real EMR studio engine sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_safe(ctx, engine_sg))
    ec2.authorize_security_group_ingress(
        GroupId=engine_sg, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": ws_sg}]}]
    )
    return ws_sg, engine_sg


def _delete_sg_safe(ctx, sg_id: str, timeout_s: float = 300.0) -> None:
    """Delete a security group, retrying while the deleted studio's network interfaces still hold it."""
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _ensure_studio_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-svc-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, role_name, "arn:aws:iam::aws:policy/AdministratorAccess"))
    return role_arn


def _create_studio_with_retry(emr, timeout_s: float = 90.0, **kwargs):
    """CreateStudio, retrying while EMR has not yet observed the new IAM role (cross-service
    propagation), which real AWS answers with ValidationException / AccessDeniedException or
    InvalidRequestException "does not have permissions to assume role"."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return emr.create_studio(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            propagating = code == "AccessDeniedException" or "assume role" in message or (
                code == "ValidationException" and "role" in message.lower() and "required" not in message
            )
            if not propagating or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _delete_role_safe(ctx, role_name: str, policy_arn: str) -> None:
    iam = ctx.client("iam")
    _tolerating(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), "NoSuchEntity")
    _tolerating(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-uni-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket_safe(ctx, name))
    return name


def _delete_bucket_safe(ctx, name: str) -> None:
    """Empty the bucket (whatever the studio wrote under its DefaultS3Location), then delete it."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            victims = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if victims:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": victims}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except s3.exceptions.NoSuchBucket:
        return
    _tolerating(lambda: s3.delete_bucket(Bucket=name), "NoSuchBucket")


def _create_session_policy(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-emr-session-policy-")
    doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "elasticmapreduce:DescribeCluster", "Resource": "*"}]}
    )
    arn = iam.create_policy(PolicyName=name, PolicyDocument=doc)["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _delete_policy_safe(ctx, arn))
    return arn


def _delete_policy_safe(ctx, arn: str) -> None:
    iam = ctx.client("iam")
    _tolerating(lambda: iam.delete_policy(PolicyArn=arn), "NoSuchEntity")


def _delete_studio_safe(ctx, studio_id: str) -> None:
    emr = ctx.client("emr")
    from botocore.exceptions import ClientError

    try:
        emr.delete_studio(StudioId=studio_id)
    except ClientError as e:
        if "does not exist" not in e.response["Error"].get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
