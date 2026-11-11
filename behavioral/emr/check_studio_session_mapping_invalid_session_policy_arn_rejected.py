"""studio-session-mapping-invalid-session-policy-arn-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "studio-session-mapping-invalid-session-policy-arn-rejected"
GROUP = "state-machine"
SERVICES = ["emr"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-emr-studio"}


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
    """CreateStudioSessionMapping with a malformed SessionPolicyArn is rejected and creates nothing,
    while the same mapping with a valid policy ARN succeeds for the same Studio and identity.
    """
    # EMR validates identity existence against the Identity Store, so the IAM Identity Center
    # instance (adopted or created) and a real user in it are provisioned in-check.
    sso_admin = ctx.client("sso-admin")
    identity_store_id, idc_arn = _get_or_create_sso_instance(ctx, sso_admin)
    identity_id = _create_identity_center_user(ctx, ctx.client("identitystore"), identity_store_id)

    emr = ctx.client("emr")
    studio_id = _create_studio(ctx, idc_arn)

    code, message = _error(
        lambda: emr.create_studio_session_mapping(
            StudioId=studio_id,
            IdentityType="USER",
            IdentityId=identity_id,
            SessionPolicyArn="not-an-arn",
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected = _service_message("SessionPolicyArn is malformed.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    # Effect absent: the malformed request must not have created a mapping. EMR's
    # session-mapping shapes model no ResourceNotFoundException, so a missing mapping
    # surfaces as the same InvalidRequestException as a malformed request.
    not_found_code, not_found_message = _error(
        lambda: emr.get_studio_session_mapping(
            StudioId=studio_id, IdentityType="USER", IdentityId=identity_id
        )
    )
    assert not_found_code == "InvalidRequestException", (
        f"expected InvalidRequestException for the absent mapping, got {not_found_code!r}"
    )
    expected = _service_message("Studio session mapping does not exist.", not_found_message)
    assert not_found_message == expected, f"expected the message {expected!r}, got {not_found_message!r}"

    # Positive control: the identical mapping succeeds with a real, valid session policy ARN.
    valid_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    emr.create_studio_session_mapping(
        StudioId=studio_id,
        IdentityType="USER",
        IdentityId=identity_id,
        SessionPolicyArn=valid_policy_arn,
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(
            StudioId=studio_id, IdentityType="USER", IdentityId=identity_id
        )
    )
    mapping = emr.get_studio_session_mapping(
        StudioId=studio_id, IdentityType="USER", IdentityId=identity_id
    )["SessionMapping"]
    assert mapping["SessionPolicyArn"] == valid_policy_arn, (
        f"expected SessionPolicyArn {valid_policy_arn!r}, got {mapping.get('SessionPolicyArn')!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _get_or_create_sso_instance(ctx, sso_admin) -> tuple[str, str]:
    """Adopt the account's IAM Identity Center instance (account-global singleton) if one
    exists; otherwise create a standalone one rather than depending on ambient SSO setup."""
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"], instances[0]["InstanceArn"]
    tags = [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]
    idc_instance_arn = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"), Tags=tags)["InstanceArn"]
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
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
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
    # us-east-1 is S3's default region and rejects an explicit LocationConstraint for it.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]},
    )
    return bucket


def _create_studio_role(ctx, prefix: str) -> str:
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="studio-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["elasticmapreduce:*", "ec2:Describe*", "s3:*", "iam:PassRole"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    return role_name


def _create_studio_security_groups(ctx, vpc_id: str) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    tag_spec = [
        {
            "ResourceType": "security-group",
            "Tags": [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
        }
    ]
    workspace_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"),
        Description="sim2real behavioral check workspace sg",
        VpcId=vpc_id,
        TagSpecifications=tag_spec,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, workspace_sg))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"),
        Description="sim2real behavioral check engine sg",
        VpcId=vpc_id,
        TagSpecifications=tag_spec,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, engine_sg))
    return workspace_sg, engine_sg


def _create_studio(ctx, idc_instance_arn: str) -> str:
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    if not vpc_id or not subnet_ids:
        raise AssertionError("no shared network VPC/subnet available in this account/region to create an EMR Studio")
    bucket = _create_test_bucket(ctx)
    service_role = _create_studio_role(ctx, "sim2real-emr-studio-svc-")
    # CreateStudio requires a UserRole whenever AuthMode=SSO.
    user_role = _create_studio_role(ctx, "sim2real-emr-studio-user-")
    workspace_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id)
    emr = ctx.client("emr")
    # A seconds-old role and its inline policy are not yet visible to EMR; retry only those
    # refusals, bounded.
    deadline = time.monotonic() + 180
    while True:
        try:
            resp = emr.create_studio(
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
                Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
            )
            break
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message", "")
            propagating = "does not have permissions to assume role" in message or (
                "does not have permission to access the 'S3 Location'" in message
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(2)
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
