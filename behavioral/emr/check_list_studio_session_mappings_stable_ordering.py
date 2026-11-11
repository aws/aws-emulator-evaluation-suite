"""list-studio-session-mappings-stable-ordering."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-studio-session-mappings-stable-ordering"
GROUP = "ordering"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListStudioSessionMappings returns a stable, deterministic order across repeated
    calls, and a newly created session mapping appears without disturbing the relative
    order of mappings that already existed."""
    emr = ctx.client("emr")
    identity_store_id, idc_instance_arn = _get_or_create_identity_center_instance(ctx)
    shared = _shared_infra(ctx, idc_instance_arn)
    studio_id = _create_sso_studio(ctx, emr, shared)
    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    def _create_mapping():
        group_id = _create_identity_store_group(ctx, identity_store_id, ctx.unique_name("sim2real-emr-grp-"))
        emr.create_studio_session_mapping(
            StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id, SessionPolicyArn=policy_arn
        )
        ctx.on_cleanup(
            lambda: _safe(
                lambda: emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id)
            )
        )
        return group_id

    group_ids = []
    for _ in range(3):
        group_ids.append(_create_mapping())
        time.sleep(1)

    def _listed_ids(relevant_ids):
        ids_seen = []
        marker = None
        while True:
            kwargs = {"StudioId": studio_id, "IdentityType": "GROUP"}
            if marker:
                kwargs["Marker"] = marker
            resp = emr.list_studio_session_mappings(**kwargs)
            ids_seen.extend(m["IdentityId"] for m in resp["SessionMappings"])
            marker = resp.get("Marker")
            if not marker:
                break
        return [s for s in ids_seen if s in relevant_ids]

    order_1 = _listed_ids(group_ids)
    order_2 = _listed_ids(group_ids)
    assert order_1 == order_2, (
        f"ListStudioSessionMappings order is not stable across repeated calls: {order_1} vs {order_2}"
    )
    assert set(order_1) == set(group_ids), f"missing session mappings: expected {group_ids}, got {order_1}"

    # add a fourth mapping and confirm the existing three keep their relative order
    new_group_id = _create_mapping()
    all_ids = group_ids + [new_group_id]

    order_3 = [s for s in _listed_ids(all_ids) if s != new_group_id]
    assert order_3 == order_1, (
        f"adding a new session mapping disturbed the relative order of pre-existing ones: "
        f"before={order_1}, after={order_3}"
    )
    listed_with_new = _listed_ids(all_ids)
    assert new_group_id in listed_with_new, "newly created session mapping did not appear in ListStudioSessionMappings"


# ===== helpers =====


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("InvalidGroup.NotFound", "InvalidSubnetID.NotFound", "InvalidVpcID.NotFound", "NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "InvalidRequestException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _get_or_create_identity_center_instance(ctx):
    """Get-or-create the account's IAM Identity Center instance. Exactly one instance is
    allowed per account, and deleting it would disrupt any other check relying on it, so
    if we must create one here we deliberately never tear it down."""
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        inst = instances[0]
        instance_arn = inst["InstanceArn"]
    else:
        instance_arn = sso.create_instance()["InstanceArn"]

    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        described = sso.describe_instance(InstanceArn=instance_arn)
        status = described["Status"]
        if status == "ACTIVE":
            return described["IdentityStoreId"], instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


def _create_identity_store_group(ctx, identity_store_id, display_name):
    idstore = ctx.client("identitystore")
    try:
        resp = idstore.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)
    except botocore.exceptions.ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "ValidationException"):
            raise AssertionError(
                "the IAM Identity Center identity store is read-only (e.g. externally synced "
                "from an IdP) and rejects CreateGroup; cannot provision a test identity for the "
                "session mapping"
            ) from exc
        raise
    group_id = resp["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)))
    return group_id


def _shared_infra(ctx, idc_instance_arn: str) -> dict:
    """Provision the VPC/subnet/security groups/bucket/roles once and reuse them for the
    single SSO-mode Studio this check creates."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    vpc_id = ec2.create_vpc(CidrBlock="10.92.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-emr-studio-vpc-")}])

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.92.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    workspace_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"), Description="workspace sg", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_security_group(GroupId=workspace_sg)))

    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"), Description="engine sg", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_security_group(GroupId=engine_sg)))

    bucket = ctx.unique_name("sim2real-emr-studio-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=bucket)))

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }

    service_role_name = ctx.unique_name("sim2real-emr-studio-svc-")
    service_role_arn = iam.create_role(
        RoleName=service_role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=service_role_name)))

    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:ListBucket",
                    "s3:GetBucketLocation",
                    "s3:GetEncryptionConfiguration",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    s3_policy_name = ctx.unique_name("sim2real-emr-studio-s3-")
    iam.put_role_policy(
        RoleName=service_role_name,
        PolicyName=s3_policy_name,
        PolicyDocument=json.dumps(s3_policy),
    )
    # DeleteRole refuses a role that still has inline policies; LIFO runs this first.
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(
        RoleName=service_role_name, PolicyName=s3_policy_name)))

    user_role_name = ctx.unique_name("sim2real-emr-studio-usr-")
    user_role_arn = iam.create_role(
        RoleName=user_role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=user_role_name)))

    return {
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "workspace_sg": workspace_sg,
        "engine_sg": engine_sg,
        "bucket": bucket,
        "service_role_arn": service_role_arn,
        "user_role_arn": user_role_arn,
        "idc_instance_arn": idc_instance_arn,
    }


def _create_sso_studio(ctx, emr, shared: dict) -> str:
    studio_id = _retry_create_studio(
        ctx,
        emr,
        Name=ctx.unique_name("sim2real-emr-studio-"),
        AuthMode="SSO",
        VpcId=shared["vpc_id"],
        SubnetIds=[shared["subnet_id"]],
        ServiceRole=shared["service_role_arn"],
        UserRole=shared["user_role_arn"],
        WorkspaceSecurityGroupId=shared["workspace_sg"],
        EngineSecurityGroupId=shared["engine_sg"],
        DefaultS3Location=f"s3://{shared['bucket']}/{ctx.unique_name('studio')}/",
        IdcInstanceArn=shared["idc_instance_arn"],
    )
    ctx.on_cleanup(lambda: _safe(lambda: emr.delete_studio(StudioId=studio_id)))
    return studio_id


def _retry_create_studio(ctx, emr, **kwargs) -> str:
    """CreateStudio, retried every 2 s for up to 60 s while IAM propagates the new service role."""
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            return emr.create_studio(**kwargs)["StudioId"]
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
