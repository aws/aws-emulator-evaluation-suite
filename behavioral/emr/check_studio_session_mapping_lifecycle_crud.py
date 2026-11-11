"""studio-session-mapping-lifecycle-crud."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "studio-session-mapping-lifecycle-crud"
GROUP = "data-plane"
SERVICES = ["emr"]


def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Create/read/update/delete a Studio session mapping and confirm it disappears from the list."""
    sso_admin = ctx.client("sso-admin")
    identity_store_id, idc_instance_arn = _get_or_create_sso_instance(ctx, sso_admin)
    identity_id = _create_identity_center_user(ctx, ctx.client("identitystore"), identity_store_id)

    emr = ctx.client("emr")
    prereqs = _studio_prereqs(ctx)
    studio_id = _create_studio_with_retry(ctx, emr, prereqs, idc_instance_arn)

    policy_arn_v1 = _create_session_policy(ctx, "v1")
    policy_arn_v2 = _create_session_policy(ctx, "v2")

    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="USER", IdentityId=identity_id, SessionPolicyArn=policy_arn_v1
    )
    deleted = {"done": False}

    def _cleanup_mapping():
        if not deleted["done"]:
            emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="USER", IdentityId=identity_id)

    ctx.on_cleanup(_cleanup_mapping)

    got = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="USER", IdentityId=identity_id)
    mapping = got["SessionMapping"]
    assert mapping["StudioId"] == studio_id, f"expected StudioId {studio_id!r}, got {mapping.get('StudioId')!r}"
    assert mapping["IdentityId"] == identity_id, (
        f"expected IdentityId {identity_id!r}, got {mapping.get('IdentityId')!r}"
    )
    assert mapping["SessionPolicyArn"] == policy_arn_v1, (
        f"expected SessionPolicyArn {policy_arn_v1!r}, got {mapping.get('SessionPolicyArn')!r}"
    )

    emr.update_studio_session_mapping(
        StudioId=studio_id, IdentityType="USER", IdentityId=identity_id, SessionPolicyArn=policy_arn_v2
    )
    got2 = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="USER", IdentityId=identity_id)
    assert got2["SessionMapping"]["SessionPolicyArn"] == policy_arn_v2, "update was not visible on read-back"

    emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="USER", IdentityId=identity_id)
    deleted["done"] = True

    remaining = emr.list_studio_session_mappings(StudioId=studio_id).get("SessionMappings", [])
    assert all(m.get("IdentityId") != identity_id for m in remaining), "deleted mapping still present in list"

    delete_code, delete_message = _error(
        lambda: emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="USER", IdentityId=identity_id)
    )
    assert delete_code == "InvalidRequestException", (
        f"expected GetStudioSessionMapping on a deleted mapping to fail InvalidRequestException, "
        f"got {delete_code!r}"
    )
    expected = _service_message("Studio session mapping does not exist.", delete_message)
    assert delete_message == expected, f"expected the message {expected!r}, got {delete_message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


_TAGS = [{"Key": "sim2real", "Value": "true"}]

_TRUST_EMR = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
)


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _studio_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-svc-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_EMR)
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="studio-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["elasticmapreduce:*", "ec2:Describe*", "s3:*", "servicecatalog:*", "iam:PassRole"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _get_or_create_sso_instance(ctx, sso_admin) -> tuple[str, str]:
    """Adopt the account's IAM Identity Center instance (account-global singleton) if one
    exists; otherwise create a standalone one rather than depending on ambient SSO setup."""
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"], instances[0]["InstanceArn"]
    idc_instance_arn = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"), Tags=_TAGS)["InstanceArn"]
    ctx.on_cleanup(lambda: sso_admin.delete_instance(InstanceArn=idc_instance_arn))
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        resp = sso_admin.describe_instance(InstanceArn=idc_instance_arn)
        if resp["Status"] == "ACTIVE":
            return resp["IdentityStoreId"], idc_instance_arn
        if resp["Status"] == "CREATE_FAILED":
            raise AssertionError(f"IAM Identity Center instance creation failed: {resp.get('StatusReason')}")
        time.sleep(5)
    raise AssertionError(f"IAM Identity Center instance {idc_instance_arn} did not become ACTIVE within 120s")


def _studio_user_role(ctx) -> str:
    # CreateStudio requires a UserRole whenever AuthMode=SSO.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-user-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_EMR, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="studio-user-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["elasticmapreduce:Describe*", "elasticmapreduce:List*"], "Resource": "*"}
                ],
            }
        ),
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_identity_center_user(ctx, identitystore, identity_store_id: str) -> str:
    user_name = ctx.unique_name("sim2real-idc-user-")
    user_id = identitystore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=user_name,
        Name={"GivenName": "Sim2Real", "FamilyName": "Probe"},
        DisplayName=user_name,
    )["UserId"]
    ctx.on_cleanup(lambda: identitystore.delete_user(IdentityStoreId=identity_store_id, UserId=user_id))
    return user_id


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host an EMR Studio")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no network subnet available")
    return vpc_id, subnets[0]["SubnetId"]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-").replace("_", "-").lower()
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":  # S3 rejects LocationConstraint for us-east-1 specifically
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _studio_prereqs(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _default_subnet(ctx)
    workspace_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"), Description="sim2real studio workspace sg", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, workspace_sg))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"), Description="sim2real studio engine sg", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, engine_sg))
    bucket = _create_bucket(ctx)
    service_role_arn = _studio_service_role(ctx)
    user_role_arn = _studio_user_role(ctx)
    return {
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "workspace_sg": workspace_sg,
        "engine_sg": engine_sg,
        "bucket": bucket,
        "service_role_arn": service_role_arn,
        "user_role_arn": user_role_arn,
    }


def _create_studio_with_retry(ctx, emr, prereqs: dict, idc_instance_arn: str) -> str:
    left = ctx.time_left()
    deadline = time.monotonic() + (60 if left is None else min(60, left))
    while True:
        try:
            resp = emr.create_studio(
                Name=ctx.unique_name("sim2real-emr-studio-"),
                AuthMode="SSO",
                VpcId=prereqs["vpc_id"],
                SubnetIds=[prereqs["subnet_id"]],
                ServiceRole=prereqs["service_role_arn"],
                UserRole=prereqs["user_role_arn"],
                WorkspaceSecurityGroupId=prereqs["workspace_sg"],
                EngineSecurityGroupId=prereqs["engine_sg"],
                DefaultS3Location=f"s3://{prereqs['bucket']}/studio/",
                IdcInstanceArn=idc_instance_arn,
            )
            studio_id = resp["StudioId"]
            ctx.on_cleanup(lambda sid=studio_id: emr.delete_studio(StudioId=sid))
            return studio_id
        except Exception:  # noqa: BLE001 - IAM role propagation retry
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_session_policy(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-emr-session-policy-{suffix}-")
    resp = iam.create_policy(
        PolicyName=name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "elasticmapreduce:DescribeCluster", "Resource": "*"}]}
        ),
    )
    arn = resp["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=arn))
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
