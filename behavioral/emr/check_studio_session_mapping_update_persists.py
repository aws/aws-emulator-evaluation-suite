"""studio-session-mapping-update-persists."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "studio-session-mapping-update-persists"
GROUP = "data-plane"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateStudioSessionMapping's new sessionPolicyArn is durably reflected on the next
    GetStudioSessionMapping call."""
    studio_id, identity_store_id = _create_sso_studio(ctx)
    group_id = _create_identity_store_group(ctx, identity_store_id, ctx.unique_name("sim2real-emr-grp-"))

    emr = ctx.client("emr")
    original_policy = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    updated_policy = "arn:aws:iam::aws:policy/AWSCloudFormationReadOnlyAccess"

    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id, SessionPolicyArn=original_policy
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id)
    )

    before = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id)[
        "SessionMapping"
    ]
    assert before["SessionPolicyArn"] == original_policy, (
        f"expected the freshly created mapping's SessionPolicyArn to be {original_policy!r}, "
        f"got {before['SessionPolicyArn']!r}"
    )

    emr.update_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id, SessionPolicyArn=updated_policy
    )

    after = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id)[
        "SessionMapping"
    ]
    assert after["SessionPolicyArn"] == updated_policy, (
        f"expected UpdateStudioSessionMapping's new SessionPolicyArn {updated_policy!r} to persist on the "
        f"next independent GetStudioSessionMapping call, got {after['SessionPolicyArn']!r}"
    )


def _get_identity_center_instance(ctx):
    """(InstanceArn, IdentityStoreId) of the account's IAM Identity Center instance.

    The instance is an account singleton, so its original state is restored: when the account has
    none, a standalone instance is created for this check and deleted on teardown; an instance that
    already existed is used and left in place.
    """
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if not instances:
        arn = sso.create_instance(Name=ctx.unique_name("sim2real-emr-idc-"))["InstanceArn"]
        ctx.on_cleanup(lambda: sso.delete_instance(InstanceArn=arn))
        deadline = time.monotonic() + 300
        while True:
            instances = [i for i in sso.list_instances().get("Instances", []) if i["InstanceArn"] == arn]
            if instances and instances[0].get("Status") == "ACTIVE" and instances[0].get("IdentityStoreId"):
                break
            if time.monotonic() > deadline:
                raise AssertionError(f"IAM Identity Center instance {arn} not ACTIVE within 300s: {instances!r}")
            time.sleep(5)
    inst = instances[0]
    return inst["InstanceArn"], inst["IdentityStoreId"]


def _create_identity_store_group(ctx, identity_store_id, display_name):
    idstore = ctx.client("identitystore")
    try:
        resp = idstore.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "ValidationException"):
            raise AssertionError(
                "the IAM Identity Center identity store is read-only (e.g. externally synced from "
                "an IdP) and rejects CreateGroup; cannot provision a test identity for the mapping"
            ) from exc
        raise
    group_id = resp["GroupId"]
    ctx.on_cleanup(lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id))
    return group_id


_TAGS = [{"Key": "sim2real", "Value": "true"}]


def _delete_retrying_dependency_violation(fn, *, timeout_s=45, interval_s=5):
    """DeleteStudio's ENIs release asynchronously, so a security group it referenced can answer
    DependencyViolation for a short window after the studio is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_network(ctx):
    """A dedicated VPC + subnet, so the check does not depend on an ambient default VPC that a
    freshly provisioned account may not have. Free: no NAT gateway, no Elastic IP."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.192.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}])[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _delete_retrying_dependency_violation(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "region-name", "Values": [ctx.region]},
                {"Name": "zone-type", "Values": ["availability-zone"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones},
            ]
        )["AvailabilityZones"]
        if z["State"] == "available"
    ]
    if not azs:
        raise AssertionError(f"no available availability zone in {ctx.region} to place the EMR Studio subnet")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.192.20.0/24",
        AvailabilityZone=sorted(azs)[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_retrying_dependency_violation(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    )
    return vpc_id, subnet_id


def _create_studio_security_groups(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-ws-"),
        Description="emr studio workspace sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}],
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _delete_retrying_dependency_violation(lambda: ec2.delete_security_group(GroupId=ws_sg))
    )
    eng_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-eng-"),
        Description="emr studio engine sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}],
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _delete_retrying_dependency_violation(lambda: ec2.delete_security_group(GroupId=eng_sg))
    )
    return ws_sg, eng_sg


def _create_studio_role(ctx, prefix):
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_studio_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-studio-").lower()
    if ctx.region == "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint for us-east-1 itself;
        # this branches on the S3 API quirk, not on a pinned test region (checks run us-west-2).
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _create_studio_with_role_wait(emr, **kwargs):
    """CreateStudio, retrying while the freshly created roles and the service role's S3 grant
    propagate, which EMR reports as InvalidRequestException naming the role or the S3 location."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            return emr.create_studio(**kwargs)
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if not propagation
            err = (getattr(exc, "response", None) or {}).get("Error", {})
            message = err.get("Message", "")
            propagating = err.get("Code") == "InvalidRequestException" and (
                "does not have permissions to assume role" in message
                or "does not have permission to access the 'S3 Location'" in message)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _grant_bucket_access(ctx, role_name, bucket):
    """CreateStudio checks that the service role can reach DefaultS3Location."""
    iam = ctx.client("iam")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
                       "s3:GetBucketLocation", "s3:GetEncryptionConfiguration"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-studio-s3", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-studio-s3"))


def _create_sso_studio(ctx):
    idc_arn, identity_store_id = _get_identity_center_instance(ctx)
    vpc_id, subnet_id = _create_network(ctx)
    ws_sg, eng_sg = _create_studio_security_groups(ctx, vpc_id)
    service_role_arn = _create_studio_role(ctx, "sim2real-stdsvc-")
    user_role_arn = _create_studio_role(ctx, "sim2real-stduser-")
    bucket = _create_studio_bucket(ctx)
    _grant_bucket_access(ctx, service_role_arn.split("/")[-1], bucket)

    emr = ctx.client("emr")
    resp = _create_studio_with_role_wait(
        emr,
        Name=ctx.unique_name("sim2real-emr-studio-"),
        AuthMode="SSO",
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        ServiceRole=service_role_arn,
        UserRole=user_role_arn,
        WorkspaceSecurityGroupId=ws_sg,
        EngineSecurityGroupId=eng_sg,
        DefaultS3Location=f"s3://{bucket}/",
        IdcInstanceArn=idc_arn,
        Tags=_TAGS,
    )
    studio_id = resp["StudioId"]
    ctx.on_cleanup(lambda: emr.delete_studio(StudioId=studio_id))
    return studio_id, identity_store_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
