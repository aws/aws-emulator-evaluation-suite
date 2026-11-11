"""studio-session-mapping-missing-identity-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# EMR probes the ServiceRole's/UserRole's assumability, which fails until a
# seconds-old role has propagated. Retry only that classified failure — the
# message must mention assumability specifically, not any error that happens
# to mention "role" (a permanent missing-parameter ValidationException does
# too, and must not be retried away).
_ROLE_PROPAGATION_CODES = {"InvalidRequestException", "ValidationException"}
_ROLE_PROPAGATION_HINTS = ("assum",)

CHECK = "studio-session-mapping-missing-identity-rejected"
GROUP = "representation"
SERVICES = ["emr"]


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
    """CreateStudioSessionMapping with neither IdentityId nor IdentityName is rejected."""
    idc_arn, identity_store_id = _identity_center_instance(ctx)

    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    ws_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id)
    service_role_arn = _ensure_studio_role(ctx, "svc", "elasticmapreduce.amazonaws.com")
    user_role_arn = _ensure_studio_role(ctx, "user", "elasticmapreduce.amazonaws.com")
    bucket = _create_bucket(ctx)
    session_policy_arn = _create_session_policy(ctx)

    emr = ctx.client("emr")
    studio_name = ctx.unique_name("sim2real-emr-studio-neg-")
    deadline = time.monotonic() + 300
    last_err = None
    while True:
        try:
            studio_id = emr.create_studio(
                Name=studio_name,
                AuthMode="SSO",
                VpcId=vpc_id,
                SubnetIds=[subnet_id],
                ServiceRole=service_role_arn,
                UserRole=user_role_arn,
                WorkspaceSecurityGroupId=ws_sg,
                EngineSecurityGroupId=engine_sg,
                DefaultS3Location=f"s3://{bucket}/studio/",
                IdcInstanceArn=idc_arn,
            )["StudioId"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            message = exc.response.get("Error", {}).get("Message", "").lower()
            propagating = code in _ROLE_PROPAGATION_CODES and any(
                hint in message for hint in _ROLE_PROPAGATION_HINTS
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            last_err = exc
            time.sleep(2)
    assert studio_id, f"CreateStudio never succeeded: {last_err}"
    ctx.on_cleanup(lambda: _delete_studio_safe(ctx, studio_id))

    # (a)+(b) neither IdentityId nor IdentityName supplied -> rejected, and no mapping appears.
    code, message = _error(
        lambda: emr.create_studio_session_mapping(
            StudioId=studio_id, IdentityType="USER", SessionPolicyArn=session_policy_arn
        )
    )
    assert code == "InvalidRequestException"
    expected = _service_message(
        "Either IdentityName or IdentityId must be specified and only one of them must be specified.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    listed = emr.list_studio_session_mappings(StudioId=studio_id).get("SessionMappings", [])
    assert listed == []

    # (c) positive control in the same file: a mapping with a real identity group succeeds.
    group_name, group_id = _create_identity_group(ctx, identity_store_id, "sim2real-emr-neg-group")
    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityName=group_name, SessionPolicyArn=session_policy_arn
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityName=group_name)
    )
    mapping = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityName=group_name)[
        "SessionMapping"
    ]
    assert mapping["IdentityId"] == group_id


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _identity_center_instance(ctx) -> tuple[str, str]:
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    instance_arn = instances[0]["InstanceArn"] if instances else sso.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        described = sso.describe_instance(InstanceArn=instance_arn)
        status = described["Status"]
        if status == "ACTIVE":
            return instance_arn, described["IdentityStoreId"]
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


def _create_identity_group(ctx, identity_store_id: str, prefix: str) -> tuple[str, str]:
    identitystore = ctx.client("identitystore")
    name = ctx.unique_name(f"{prefix}-")
    group_id = identitystore.create_group(IdentityStoreId=identity_store_id, DisplayName=name)["GroupId"]
    ctx.on_cleanup(lambda: _delete_group_safe(ctx, identity_store_id, group_id))
    return name, group_id


def _delete_group_safe(ctx, identity_store_id: str, group_id: str) -> None:
    identitystore = ctx.client("identitystore")
    try:
        identitystore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _delete_sg_safe(ctx, sg_id: str) -> None:
    ec2 = ctx.client("ec2")
    _delete_security_group_when_free(ec2, sg_id)


def _ensure_studio_role(ctx, tag: str, principal: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-emr-studio-{tag}-")
    trust = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, role_name, "arn:aws:iam::aws:policy/AdministratorAccess"))
    return role_arn


def _delete_role_safe(ctx, role_name: str, policy_arn: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-neg-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket_safe(ctx, name))
    return name


def _delete_bucket_safe(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


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
    try:
        iam.delete_policy(PolicyArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_studio_safe(ctx, studio_id: str) -> None:
    emr = ctx.client("emr")
    try:
        emr.delete_studio(StudioId=studio_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "InvalidRequestException"
            and "does not exist" in err.get("Message", "")
        ):
            raise



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
