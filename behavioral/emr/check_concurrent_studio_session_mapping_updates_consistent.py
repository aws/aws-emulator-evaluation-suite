"""concurrent-studio-session-mapping-updates-consistent."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-studio-session-mapping-updates-consistent"
GROUP = "concurrency"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Two concurrent UpdateStudioSessionMapping calls on the same mapping settle on one
    value: three independent GetStudioSessionMapping reads all agree, and the value they
    agree on is one of the two racers' SessionPolicyArns, for both a USER and a GROUP mapping.
    """
    idc_arn, identity_store_id = _identity_center_instance(ctx)
    group_id = _create_identity_group(ctx, identity_store_id)
    user_id = _create_identity_user(ctx, identity_store_id)
    studio_id = _create_sso_studio(ctx, idc_arn)
    policy_arn_a = _create_session_policy(ctx, "a")
    policy_arn_b = _create_session_policy(ctx, "b")

    for identity_type, identity_id in (("GROUP", group_id), ("USER", user_id)):
        _assert_concurrent_updates_settle(
            ctx, studio_id, identity_type, identity_id, policy_arn_a, policy_arn_b
        )


def _assert_concurrent_updates_settle(
    ctx, studio_id: str, identity_type: str, identity_id: str, policy_arn_a: str, policy_arn_b: str
) -> None:
    emr = ctx.client("emr")
    emr.create_studio_session_mapping(
        StudioId=studio_id,
        IdentityId=identity_id,
        IdentityType=identity_type,
        SessionPolicyArn=policy_arn_a,
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: emr.delete_studio_session_mapping(
                StudioId=studio_id, IdentityId=identity_id, IdentityType=identity_type
            )
        )
    )

    def _update(policy_arn: str) -> None:
        emr.update_studio_session_mapping(
            StudioId=studio_id,
            IdentityId=identity_id,
            IdentityType=identity_type,
            SessionPolicyArn=policy_arn,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, policy_arn_a), pool.submit(_update, policy_arn_b)]
        for f in futures:
            f.result()

    reads = []
    for _ in range(3):
        mapping = emr.get_studio_session_mapping(
            StudioId=studio_id, IdentityId=identity_id, IdentityType=identity_type
        )["SessionMapping"]
        reads.append(mapping["SessionPolicyArn"])
        time.sleep(0.5)

    assert len(set(reads)) == 1, (
        f"{identity_type}: GetStudioSessionMapping returned inconsistent values across "
        f"independent reads after the race settled: {reads}"
    )
    assert reads[0] in (policy_arn_a, policy_arn_b), (
        f"{identity_type}: final SessionPolicyArn {reads[0]!r} is neither racer's value "
        f"({policy_arn_a!r} or {policy_arn_b!r}) -- a mixed/corrupted representation"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("InvalidGroup.NotFound", "NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "InvalidRequestException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, reason: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last observed: {last!r}")


def _identity_center_instance(ctx) -> tuple[str, str]:
    """Adopt this account's IAM Identity Center instance (SSO-mode studios need one), creating one
    if it has none. CreateInstance allows one per account across all regions, so adopt comes first;
    a created instance is never torn down because concurrent checks in the account share it."""
    sso = ctx.client("sso-admin")
    try:
        instances = sso.list_instances().get("Instances", [])
    except ClientError as exc:
        raise AssertionError(
            f"cannot query IAM Identity Center instances ({exc.response['Error']['Code']}); "
            "EMR Studio session mappings require SSO auth mode backed by an Identity Center instance"
        ) from exc
    if not instances:
        sso.create_instance(Name=ctx.unique_name("sim2real-emr-studio-idc-"))

    def _probe():
        found = sso.list_instances().get("Instances", [])
        for inst in found:
            if inst.get("Status") == "CREATE_FAILED":
                raise AssertionError(f"IAM Identity Center instance creation failed: {inst}")
        return found

    instances = _poll_until(
        _probe,
        lambda found: any(i.get("Status") == "ACTIVE" and "IdentityStoreId" in i for i in found),
        timeout_s=120,
        interval_s=5,
        reason="an ACTIVE IAM Identity Center instance carrying an IdentityStoreId",
    )
    active = next(i for i in instances if i.get("Status") == "ACTIVE" and "IdentityStoreId" in i)
    return active["InstanceArn"], active["IdentityStoreId"]


def _create_identity_group(ctx, identity_store_id: str) -> str:
    """A GROUP this check owns, rather than adopting whatever group the account happens to
    hold -- an adopted identity can be deleted mid-run by the sibling that created it."""
    idstore = ctx.client("identitystore")
    group_id = idstore.create_group(
        IdentityStoreId=identity_store_id, DisplayName=ctx.unique_name("sim2real-emr-studio-group-")
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id))
    )
    return group_id


def _create_identity_user(ctx, identity_store_id: str) -> str:
    """A USER this check owns. Identity Store users and groups ARE deletable (unlike the
    instance above), so both are torn down."""
    idstore = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-emr-studio-user-")
    user_id = idstore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=username,
        Name={"GivenName": "Sim2Real", "FamilyName": "Test"},
        DisplayName=username,
        Emails=[{"Value": f"{username}@example.com", "Primary": True}],
    )["UserId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: idstore.delete_user(IdentityStoreId=identity_store_id, UserId=user_id))
    )
    return user_id


def _default_vpc_and_subnet(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to attach an EMR Studio to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError(f"shared network {vpc_id} has no subnets to attach an EMR Studio to")
    return vpc_id, subnets[0]["SubnetId"]


def _create_studio_security_groups(ctx, vpc_id: str) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    tag_spec = [{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}]
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"),
        Description="sim2real EMR studio workspace sg",
        VpcId=vpc_id,
        TagSpecifications=tag_spec,
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_security_group_when_free(ec2, ws_sg)))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"),
        Description="sim2real EMR studio engine sg",
        VpcId=vpc_id,
        TagSpecifications=tag_spec,
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_security_group_when_free(ec2, engine_sg)))
    ec2.authorize_security_group_ingress(
        GroupId=engine_sg, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": ws_sg}]}]
    )
    return ws_sg, engine_sg


def _create_studio_role(ctx, prefix: str) -> str:
    """A studio role plus its managed-policy attachment, torn down by ONE cleanup that
    detaches before deleting. Registering the detach and the delete as two cleanups is how
    an ordering bug gets in: DeleteRole refuses while a policy is attached."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
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
    # AdministratorAccess, not a scoped policy: CreateStudio validates the ServiceRole against
    # DefaultS3Location up front and rejects it even with AmazonS3ReadOnlyAccess attached. The
    # studio's authorization surface is not what this check asserts.
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, policy_arn))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _delete_role(ctx, role_name: str, policy_arn: str) -> None:
    iam = ctx.client("iam")
    _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _safe(lambda: iam.delete_role(RoleName=role_name))


def _create_studio_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-studio-").lower().replace("_", "-")
    # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint for it.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    return bucket


def _delete_bucket(ctx, bucket: str) -> None:
    """Empty then delete: DeleteBucket refuses a non-empty bucket, and the studio's
    DefaultS3Location means AWS -- not this check -- decides whether anything was written."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
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


def _create_sso_studio(ctx, idc_arn: str) -> str:
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    ws_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id)
    service_role_arn = _create_studio_role(ctx, "sim2real-emr-studio-svc-")
    # AWS::EMR::Studio does not mark UserRole required, but real AWS rejects AuthMode SSO
    # without it: "UserRole is required to create a studio with SSO auth-mode".
    user_role_arn = _create_studio_role(ctx, "sim2real-emr-studio-usr-")
    bucket = _create_studio_bucket(ctx)
    emr = ctx.client("emr")
    studio_id = _create_studio_with_role_wait(
        emr,
        Name=ctx.unique_name("sim2real-emr-studio-"),
        AuthMode="SSO",
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        ServiceRole=service_role_arn,
        UserRole=user_role_arn,
        WorkspaceSecurityGroupId=ws_sg,
        EngineSecurityGroupId=engine_sg,
        DefaultS3Location=f"s3://{bucket}/studio/",
        IdcInstanceArn=idc_arn,
        IdcUserAssignment="OPTIONAL",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StudioId"]
    ctx.on_cleanup(lambda: _safe(lambda: emr.delete_studio(StudioId=studio_id)))
    return studio_id


def _create_studio_with_role_wait(emr, **kwargs):
    """CreateStudio, retrying only while the new roles' trust propagates to EMR. The lag can be an
    InvalidRequestException "does not have permissions to assume role", so the message is matched:
    a genuine bad request is also an InvalidRequestException and must fail immediately."""
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


def _create_session_policy(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "elasticmapreduce:DescribeCluster", "Resource": "*"}],
    }
    name = ctx.unique_name(f"sim2real-emr-studio-policy-{suffix}-")
    arn = iam.create_policy(
        PolicyName=name, PolicyDocument=json.dumps(doc), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_policy(PolicyArn=arn)))
    return arn



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
