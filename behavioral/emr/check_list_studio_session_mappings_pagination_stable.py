"""list-studio-session-mappings-pagination-stable."""
from __future__ import annotations

import time
import json
import time as _time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-studio-session-mappings-pagination-stable"
GROUP = "ordering"
SERVICES = ["emr"]

_MIN_IDENTITIES = 3


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Paginating ListStudioSessionMappings by Marker to exhaustion returns every created mapping
    exactly once (no duplicates, no gaps), however the service splits the pages.
    """
    instance_arn, store_id = _get_or_create_idc_instance(ctx)
    emr = ctx.client("emr")
    studio_id = _create_studio(ctx, instance_arn)
    session_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    idstore = ctx.client("identitystore")
    created_ids = set()
    for _ in range(_MIN_IDENTITIES):
        username = ctx.unique_name("sim2real-emr-studio-user-")
        identity_id = idstore.create_user(
            IdentityStoreId=store_id,
            UserName=username,
            DisplayName="Sim2Real EMR Studio Test User",
            Name={"GivenName": "Sim", "FamilyName": "User"},
        )["UserId"]
        ctx.on_cleanup(
            lambda uid=identity_id: _safe(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=uid))
        )

        emr.create_studio_session_mapping(
            StudioId=studio_id,
            IdentityType="USER",
            IdentityId=identity_id,
            SessionPolicyArn=session_policy_arn,
        )
        ctx.on_cleanup(
            lambda iid=identity_id: emr.delete_studio_session_mapping(
                StudioId=studio_id, IdentityType="USER", IdentityId=iid
            )
        )
        created_ids.add(identity_id)

    seen: list[str] = []
    marker = None
    pages = 0
    while True:
        kwargs: dict[str, Any] = {"StudioId": studio_id}
        if marker:
            kwargs["Marker"] = marker
        page = emr.list_studio_session_mappings(**kwargs)
        pages += 1
        for m in page.get("SessionMappings", []):
            if m["IdentityId"] in created_ids:
                seen.append(m["IdentityId"])
        marker = page.get("Marker")
        if not marker or pages > 200:
            break

    assert len(seen) == len(created_ids), (
        f"expected each of {len(created_ids)} created mappings exactly once across "
        f"{pages} page(s), saw {len(seen)} total matches: {seen}"
    )
    assert set(seen) == created_ids, f"gap detected: missing {created_ids - set(seen)}"
    assert len(seen) == len(set(seen)), f"duplicate detected across pages: {seen}"


# ===== helpers =====
def _safe(fn) -> None:
    """Run a teardown delete: a resource that is already gone is fine, any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _get_or_create_idc_instance(ctx) -> tuple[str, str]:
    ssoadmin = ctx.client("sso-admin")
    try:
        resp = ssoadmin.list_instances()
    except Exception as exc:
        raise AssertionError(
            f"ssoadmin.list_instances is unavailable ({exc}); EMR Studio validates a session "
            "mapping's IdentityId against the Identity Store behind an IAM Identity Center "
            "instance, and this check cannot reach the Identity Center control plane at all"
        ) from exc
    instances = resp.get("Instances", [])
    if instances:
        inst = instances[0]
        return inst["InstanceArn"], inst["IdentityStoreId"]
    try:
        created = ssoadmin.create_instance(
            Name=ctx.unique_name("sim2real-idc-"),
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
    except Exception as exc:
        raise AssertionError(
            f"no IAM Identity Center instance exists and ssoadmin.create_instance failed ({exc}); "
            "this is expected for AWS Organizations management/member accounts, which reject "
            "self-service instance creation -- run against a standalone account or an emulator "
            "that seeds a default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
    deadline = _time.monotonic() + 60
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        for inst in resp.get("Instances", []):
            if inst.get("InstanceArn") != instance_arn:
                continue
            status = inst.get("Status")
            if status == "CREATE_FAILED":
                raise AssertionError(
                    f"IAM Identity Center instance {instance_arn} failed to provision: "
                    f"{inst.get('StatusReason')}"
                )
            if status == "ACTIVE" and "IdentityStoreId" in inst:
                return instance_arn, inst["IdentityStoreId"]
        _time.sleep(2)
    raise AssertionError(
        f"IAM Identity Center instance {instance_arn} never reached ACTIVE with an "
        "IdentityStoreId via list_instances within 60s"
    )


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
        for pol_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name)
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _caller_principal_arn(ctx) -> str:
    """The underlying IAM role/user ARN behind the calling identity.

    An assumed-role session ARN (``sts::ACCT:assumed-role/Role/Session``) is not a valid trust
    policy principal on its own -- IAM trust evaluates the underlying role identity, so it must be
    rewritten to ``iam::ACCT:role/Role``.
    """
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    if ":assumed-role/" not in caller_arn:
        return caller_arn
    account_id = caller_arn.split(":")[4]
    role_name = caller_arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _create_studio_with_iam_propagation_retry(emr, **kwargs):
    """CreateStudio validates the caller can assume UserRole, and that ServiceRole can reach the S3
    location, against IAM documents we just wrote -- IAM changes are eventually consistent, so the
    first call can race their propagation. Bounded retry, not a sleep: give up after 120s if it is
    a real permissions problem rather than propagation lag.
    """
    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + 120
    while True:
        try:
            return emr.create_studio(**kwargs)
        except ClientError as exc:
            msg = str(exc)
            if "does not have permission" not in msg or _time.monotonic() >= deadline:
                raise
            _time.sleep(5)


def _grant_service_role_s3_access(ctx, role_name: str, bucket: str) -> None:
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-emr-studio-s3",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    },
                ],
            }
        ),
    )


def _create_emr_assumable_role(ctx, prefix: str, *, extra_principal_arn: str | None = None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    statements = [
        {
            "Effect": "Allow",
            "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ]
    if extra_principal_arn:
        statements.append(
            {
                "Effect": "Allow",
                "Principal": {"AWS": extra_principal_arn},
                "Action": "sts:AssumeRole",
            }
        )
    trust = json.dumps({"Version": "2012-10-17", "Statement": statements})
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, role_name))
    return role_name


def _create_studio_security_groups(ctx, vpc_id: str) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    workspace_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"),
        Description="sim2real behavioral check workspace sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, workspace_sg))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"),
        Description="sim2real behavioral check engine sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, engine_sg))
    return workspace_sg, engine_sg


def _create_studio(ctx, idc_instance_arn: str) -> str:
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    if not vpc_id or not subnet_ids:
        raise AssertionError("no shared network VPC/subnet available in this account/region to create an EMR Studio")
    bucket = _create_test_bucket(ctx)
    service_role = _create_emr_assumable_role(ctx, "sim2real-emr-studio-svc-")
    _grant_service_role_s3_access(ctx, service_role, bucket)
    user_role = _create_emr_assumable_role(
        ctx, "sim2real-emr-studio-usr-", extra_principal_arn=_caller_principal_arn(ctx)
    )
    workspace_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id)
    emr = ctx.client("emr")
    resp = _create_studio_with_iam_propagation_retry(
        emr,
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
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
