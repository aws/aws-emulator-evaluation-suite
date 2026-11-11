"""studio-session-mapping-delete-then-get-not-found."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "studio-session-mapping-delete-then-get-not-found"
GROUP = "state-machine"
SERVICES = ["emr"]


def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """After DeleteStudioSessionMapping on a mapping between a real Studio and a real identity, the get
    for that mapping fails with InvalidRequestException and AWS's exact not-exist message."""
    idc_arn, identity_id = _ensure_idc_identity(ctx)

    emr = ctx.client("emr")
    studio_id = _create_studio(ctx, idc_arn)
    session_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    emr.create_studio_session_mapping(
        StudioId=studio_id,
        IdentityType="USER",
        IdentityId=identity_id,
        SessionPolicyArn=session_policy_arn,
    )

    # Confirm the mapping is visible before we delete it.
    mapping = emr.get_studio_session_mapping(
        StudioId=studio_id, IdentityType="USER", IdentityId=identity_id
    )
    got_identity_id = mapping["SessionMapping"]["IdentityId"]
    assert got_identity_id == identity_id, f"expected IdentityId {identity_id!r}, got {got_identity_id!r}"

    emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="USER", IdentityId=identity_id)

    code, message = _error(
        lambda: emr.get_studio_session_mapping(
            StudioId=studio_id, IdentityType="USER", IdentityId=identity_id
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected = _service_message("Studio session mapping does not exist.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _wait_instance_active(sso, instance_arn: str) -> str:
    deadline = time.monotonic() + 120
    last_status = None
    while time.monotonic() < deadline:
        desc = sso.describe_instance(InstanceArn=instance_arn)
        last_status = desc["Status"]
        if last_status == "ACTIVE":
            return desc["IdentityStoreId"]
        if last_status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise AssertionError(f"IAM Identity Center instance {instance_arn} entered {last_status}")
        time.sleep(3)
    raise AssertionError(
        f"IAM Identity Center instance {instance_arn} did not reach ACTIVE within 120s "
        f"(last status: {last_status!r})"
    )


def _ensure_idc_identity(ctx) -> tuple[str, str]:
    """Adopt an existing IAM Identity Center instance, or provision one.

    The instance is an account-global singleton (one per account, like the Config recorder) --
    an adopted or newly created instance is left in place rather than torn down. The user is
    this check's own resource and is deleted via ctx.on_cleanup.
    """
    sso = ctx.client("sso-admin")
    idstore = ctx.client("identitystore")

    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
        identity_store_id = instances[0]["IdentityStoreId"]
    else:
        created = sso.create_instance(Name=ctx.unique_name("sim2real-emr-idc-"))
        instance_arn = created["InstanceArn"]
        identity_store_id = _wait_instance_active(sso, instance_arn)

    user_name = ctx.unique_name("sim2real-emr-user-")
    user = idstore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=user_name,
        DisplayName=user_name,
        Name={"GivenName": "Sim2Real", "FamilyName": "Test"},
        Emails=[{"Value": f"{user_name}@example.com", "Type": "work", "Primary": True}],
    )
    user_id = user["UserId"]
    ctx.on_cleanup(lambda: idstore.delete_user(IdentityStoreId=identity_store_id, UserId=user_id))
    return instance_arn, user_id


def _default_vpc_and_subnets(ctx) -> tuple[str | None, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None, []
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    return vpc_id, [s["SubnetId"] for s in subnets]


def _delete_iam_role(ctx, role_name: str) -> None:
    import contextlib

    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
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


def _create_test_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-studio-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _create_emr_trusted_role(ctx, prefix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, role_name))
    return role_name


def _grant_bucket_access(ctx, role_name: str, bucket: str) -> None:
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-emr-studio-s3-")
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket", "s3:GetBucketLocation", "s3:GetEncryptionConfiguration"],
                    "Resource": f"arn:aws:s3:::{bucket}",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
                    "Resource": "*",
                },
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))


def _safe(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_studio_security_groups(ctx, vpc_id: str) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    workspace_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"),
        Description="sim2real behavioral check workspace sg",
        VpcId=vpc_id,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, workspace_sg))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"),
        Description="sim2real behavioral check engine sg",
        VpcId=vpc_id,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, engine_sg))
    return workspace_sg, engine_sg


_ROLE_PROPAGATION_MARKERS = (
    "does not have permissions to assume role",
    "does not have permission to access the 'S3 Location'",
)


def _retry_role_propagation(fn):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code != "InvalidRequestException" or not any(m in message for m in _ROLE_PROPAGATION_MARKERS):
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"IAM role/policy never propagated within 90s: {message}") from err
            time.sleep(5)


def _create_studio(ctx, idc_instance_arn: str) -> str:
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    if not vpc_id or not subnet_ids:
        raise AssertionError("no shared network VPC/subnet available in this account/region to create an EMR Studio")
    bucket = _create_test_bucket(ctx)
    service_role = _create_emr_trusted_role(ctx, "sim2real-emr-studio-svc-")
    _grant_bucket_access(ctx, service_role, bucket)
    user_role = _create_emr_trusted_role(ctx, "sim2real-emr-studio-usr-")
    workspace_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id)
    emr = ctx.client("emr")

    def _create() -> dict[str, Any]:
        return emr.create_studio(
            Name=ctx.unique_name("sim2real-emr-studio-"),
            AuthMode="SSO",
            VpcId=vpc_id,
            SubnetIds=subnet_ids[:2] if len(subnet_ids) >= 2 else subnet_ids,
            ServiceRole=service_role,
            UserRole=user_role,
            WorkspaceSecurityGroupId=workspace_sg,
            EngineSecurityGroupId=engine_sg,
            DefaultS3Location=f"s3://{bucket}/studio/",
            IdcInstanceArn=idc_instance_arn,
        )

    # The service/user roles were just created; IAM's cross-service assume-role trust needs a
    # moment to propagate before EMR can assume them, so retry the specific "cannot assume role"
    # rejection on a bounded deadline rather than a single unconditional sleep.
    resp = _retry_role_propagation(_create)
    studio_id = resp["StudioId"]
    ctx.on_cleanup(lambda: emr.delete_studio(StudioId=studio_id))
    return studio_id



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
