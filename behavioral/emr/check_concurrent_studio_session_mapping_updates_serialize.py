"""concurrent-studio-session-mapping-updates-serialize."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-studio-session-mapping-updates-serialize"
GROUP = "concurrency"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Concurrent UpdateStudioSessionMapping calls for the same identity serialize to a
    single final sessionPolicyArn rather than a mixed/torn value."""
    fixture = _create_studio_fixture(ctx)
    emr = ctx.client("emr")
    studio_id = fixture["studio_id"]
    identity_type = fixture["identity_type"]
    identity_name = fixture["identity_name"]

    initial_policy = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name,
        SessionPolicyArn=initial_policy,
    )
    ctx.on_cleanup(lambda: _safe(lambda: emr.delete_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name
    )))

    policy_b = "arn:aws:iam::aws:policy/AWSSupportAccess"
    policy_c = "arn:aws:iam::aws:policy/ViewOnlyAccess"

    def _update(policy_arn):
        emr.update_studio_session_mapping(
            StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name,
            SessionPolicyArn=policy_arn,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, policy_b), pool.submit(_update, policy_c)]
        for f in futures:
            f.result()

    reads = []
    for _ in range(3):
        mapping = emr.get_studio_session_mapping(
            StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name
        )["SessionMapping"]
        reads.append(mapping["SessionPolicyArn"])
        time.sleep(0.5)

    assert len(set(reads)) == 1, (
        f"GetStudioSessionMapping returned inconsistent values across independent reads after "
        f"the race settled: {reads} -- a torn/mixed representation, not a serialized one"
    )
    assert reads[0] in (policy_b, policy_c), (
        f"final SessionPolicyArn {reads[0]!r} matches neither racing writer's value "
        f"({policy_b!r} or {policy_c!r}) -- corrupted state"
    )


# ===== helpers =====

def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "InvalidRequestException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _delete_sg_pair(ctx, engine_sg, ws_sg):
    """Delete the engine group then the workspace group, retrying DependencyViolation.

    Order is load-bearing (engine_sg's ingress rule references ws_sg). The retry is for the OTHER
    dependency: DeleteStudio returns before the studio's ENIs detach from these groups, so the
    first attempt can legitimately get DependencyViolation for a resource that is genuinely going
    away. The `emr` cleanup budget is 900s, so a 120s retry fits inside it.
    """
    ec2 = ctx.client("ec2")
    for sg_id in (engine_sg, ws_sg):
        deadline = time.monotonic() + 120.0
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    break
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
                time.sleep(5)


def _empty_and_delete_bucket(ctx, bucket):
    """Empty then delete: DeleteBucket refuses a non-empty bucket, and whether anything landed
    under the studio's DefaultS3Location is AWS's decision, not this check's -- so a
    delete-only teardown strands the bucket whenever AWS did write."""
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
    _safe(lambda: s3.delete_bucket(Bucket=bucket))


def _default_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to attach an EMR Studio")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    return vpc_id, subnets[0]["SubnetId"]


def _create_studio_with_retry(ctx, emr, vpc_id, subnet_id, role_name, bucket, engine_sg, ws_sg, idc_instance_arn):
    """CreateStudio, retrying only the transient IAM-role-propagation error.

    A freshly created role is not yet assumable everywhere; retrying the real dependent call bounds
    the wait to what this run actually needed instead of a fixed guess."""
    deadline = time.monotonic() + 60
    last = None
    while time.monotonic() < deadline:
        try:
            studio = emr.create_studio(
                Name=ctx.unique_name("sim2real-emr-studio-"),
                AuthMode="SSO",
                VpcId=vpc_id,
                SubnetIds=[subnet_id],
                ServiceRole=role_name,
                UserRole=role_name,
                DefaultS3Location=f"s3://{bucket}/studio/",
                EngineSecurityGroupId=engine_sg,
                WorkspaceSecurityGroupId=ws_sg,
                IdcInstanceArn=idc_instance_arn,
                IdcUserAssignment="OPTIONAL",
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
            return studio["StudioId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = str(exc)
            transient = code in ("AccessDenied", "AccessDeniedException", "InvalidRequestException") and (
                "is not authorized" in message or "assume" in message.lower()
            )
            if not transient:
                raise
            last = exc
            time.sleep(5)
    raise AssertionError(f"CreateStudio never succeeded within the IAM-propagation budget: {last}")


def _find_idc_identity(ctx):
    """Create-or-adopt an IAM Identity Center instance, then create a user in it.

    CreateStudioSessionMapping requires SSO auth mode with a real Identity Center identity; a
    fresh account has no IAM Identity Center instance, but `sso-admin` exposes
    `CreateInstance` for exactly this (a standalone, non-org instance), so the prerequisite is
    created in-check rather than assumed ambient. CreateInstance allows exactly ONE instance per
    account across all regions and rejects the organization management account, so the adopt arm
    is tried first.

    The INSTANCE is deliberately never torn down. It is an account-global singleton that every
    concurrent check in this account shares, so deleting one this run happened to create would
    break their studios. The USER below is a different matter: Identity Store users are deletable
    and this one is deleted.
    """
    sso = ctx.client("sso-admin")
    try:
        instances = sso.list_instances().get("Instances", [])
    except ClientError as exc:
        raise AssertionError(
            f"cannot query IAM Identity Center instances ({exc.response['Error']['Code']}); "
            "CreateStudioSessionMapping requires SSO auth mode with a real Identity Center identity"
        )
    if not instances:
        sso.create_instance(Name=ctx.unique_name("sim2real-emr-studio-idc-"))
    deadline = time.monotonic() + 120
    instance_arn = identity_store_id = None
    while time.monotonic() < deadline:
        found = sso.list_instances().get("Instances", [])
        for inst in found:
            if inst.get("Status") == "CREATE_FAILED":
                raise AssertionError(f"IAM Identity Center instance creation failed: {inst}")
        active = [i for i in found if i.get("Status") == "ACTIVE" and "IdentityStoreId" in i]
        if active:
            instance_arn = active[0]["InstanceArn"]
            identity_store_id = active[0]["IdentityStoreId"]
            break
        time.sleep(3)
    if identity_store_id is None:
        raise AssertionError(
            "no IAM Identity Center instance reached ACTIVE with an IdentityStoreId within 120s"
        )

    # A user this check OWNS, rather than adopting whichever user the account happens to hold:
    # an adopted identity can be deleted mid-run by the concurrent check that created it, which
    # would fail this one for a reason that is not about UpdateStudioSessionMapping at all.
    idstore = ctx.client("identitystore")
    user_name = ctx.unique_name("sim2real-emr-studio-user-")
    user_id = idstore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=user_name,
        Name={"GivenName": "Sim2Real", "FamilyName": "Test"},
        DisplayName="Sim2Real Test",
    )["UserId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_user(IdentityStoreId=identity_store_id, UserId=user_id)))
    return {"IdentityType": "USER", "IdentityName": user_name, "instance_arn": instance_arn}


def _create_studio_fixture(ctx):
    identity = _find_idc_identity(ctx)
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    emr = ctx.client("emr")
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)

    sg_tags = [{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}]
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"), Description="emr studio engine sg", VpcId=vpc_id,
        TagSpecifications=sg_tags,
    )["GroupId"]
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"), Description="emr studio workspace sg", VpcId=vpc_id,
        TagSpecifications=sg_tags,
    )["GroupId"]
    # ONE cleanup for the pair, deleting the engine group FIRST: the engine group's ingress rule
    # below REFERENCES ws_sg, so deleting ws_sg first fails with DependencyViolation. Deleting the
    # referencing group before the referenced one is a property of the pair, so it belongs in one
    # callable rather than in a registration order a later edit can silently reverse.
    ctx.on_cleanup(lambda: _delete_sg_pair(ctx, engine_sg, ws_sg))
    ec2.authorize_security_group_ingress(
        GroupId=engine_sg, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": ws_sg}]}],
    )

    role_name = ctx.unique_name("sim2real-emr-studio-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )))

    bucket = ctx.unique_name("sim2real-emr-studio-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    studio_id = _create_studio_with_retry(
        ctx, emr, vpc_id, subnet_id, role_name, bucket, engine_sg, ws_sg, identity["instance_arn"]
    )
    ctx.on_cleanup(lambda: _safe(lambda: emr.delete_studio(StudioId=studio_id)))
    return {
        "studio_id": studio_id,
        "identity_type": identity["IdentityType"],
        "identity_name": identity["IdentityName"],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
