"""list-studio-session-mappings-reflects-membership."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-studio-session-mappings-reflects-membership"
GROUP = "data-plane"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListStudioSessionMappings enumerates exactly the mappings created for a studio,
    including newly added ones."""
    studio_id, identity_store_id = _create_sso_studio(ctx)
    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    emr = ctx.client("emr")

    group_id_1 = _create_identity_store_group(ctx, identity_store_id, ctx.unique_name("sim2real-emr-g1-"))
    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id_1, SessionPolicyArn=policy_arn
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id_1)
    )

    mappings_before = emr.list_studio_session_mappings(StudioId=studio_id)["SessionMappings"]
    ids_before = {m["IdentityId"] for m in mappings_before}
    assert ids_before == {group_id_1}, f"expected ListStudioSessionMappings to return {{{group_id_1!r}}}, got {ids_before!r}"

    group_id_2 = _create_identity_store_group(ctx, identity_store_id, ctx.unique_name("sim2real-emr-g2-"))
    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id_2, SessionPolicyArn=policy_arn
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id_2)
    )

    mappings_after = emr.list_studio_session_mappings(StudioId=studio_id)["SessionMappings"]
    ids_after = {m["IdentityId"] for m in mappings_after}
    expected_after = {group_id_1, group_id_2}
    assert ids_after == expected_after, (
        f"expected ListStudioSessionMappings to reflect the newly added group as {expected_after!r}, got {ids_after!r}"
    )


# ===== helpers =====

def _identity_center_instances(ctx):
    """The account's IAM Identity Center instances, creating one if the account has none.

    `sso-admin:CreateInstance` provisions a STANDALONE (non-Organizations) instance, so the
    prerequisite is satisfiable in-check and an account without an instance does not block the
    check. Exactly one instance is allowed per account ACROSS ALL REGIONS, and deleting it would
    disrupt any other check relying on it, so one created here is deliberately never torn down --
    unlike the Identity Store groups below, which this check owns and deletes.
    """
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



def _get_identity_center_instance(ctx):
    instances = _identity_center_instances(ctx)
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


def _default_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to attach an EMR Studio to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to attach an EMR Studio to")
    return vpc_id, subnets[0]["SubnetId"]


def _create_studio_security_groups(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-ws-"),
        Description="emr studio workspace sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, ws_sg))
    eng_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-eng-"),
        Description="emr studio engine sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, eng_sg))
    return ws_sg, eng_sg


def _create_studio_role(ctx, prefix):
    """A studio role plus its managed-policy attachment, torn down by ONE cleanup that detaches
    before deleting -- registering the detach and the delete separately is how an ordering bug
    gets in, since DeleteRole refuses while a policy is still attached.

    A trust policy alone is not enough: CreateStudio VALIDATES the ServiceRole against
    DefaultS3Location up front and rejects the studio with "'ServiceRole' does not have permission
    to access the 'S3 Location' or associated KMS key(s)" when it cannot write there. The studio's
    authorization surface is not what this check asserts, so it uses the same broad policy its
    passing siblings in this directory do rather than hand-scoping one.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _detach_and_delete_role(ctx, name, policy_arn))
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return arn


def _detach_and_delete_role(ctx, role_name, policy_arn):
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_studio_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-studio-").lower()
    # us-east-1 rejects CreateBucket with an explicit LocationConstraint for its own region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    """Empty then delete: DeleteBucket refuses a non-empty bucket, and whether anything landed
    under the studio's DefaultS3Location is AWS's decision, not this check's -- so a delete-only
    teardown strands the bucket whenever AWS did write."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            victims = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if victims:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_studio_with_role_wait(emr, **kwargs):
    """CreateStudio, retrying ONLY while the just-created ServiceRole/UserRole trust propagates.

    Real AWS surfaces that lag as ValidationException/AccessDeniedException or as
    InvalidRequestException with "does not have permissions to assume role". The match is
    on the message and not merely the code, because a genuine bad request is an
    InvalidRequestException too and must fail immediately with its own diagnosis rather than be
    buried under a 90s retry loop.
    """
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.create_studio(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            is_role_propagation = code in ("ValidationException", "AccessDeniedException") or (
                code == "InvalidRequestException" and "does not have permissions to assume role" in message
            )
            if not is_role_propagation:
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"CreateStudio did not succeed within 90s of IAM role creation: {last_err}")


def _create_sso_studio(ctx):
    idc_arn, identity_store_id = _get_identity_center_instance(ctx)
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    ws_sg, eng_sg = _create_studio_security_groups(ctx, vpc_id)
    service_role_arn = _create_studio_role(ctx, "sim2real-stdsvc-")
    user_role_arn = _create_studio_role(ctx, "sim2real-stduser-")
    bucket = _create_studio_bucket(ctx)

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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    studio_id = resp["StudioId"]
    ctx.on_cleanup(lambda: emr.delete_studio(StudioId=studio_id))
    return studio_id, identity_store_id



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

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
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
