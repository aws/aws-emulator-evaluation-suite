"""deploy-emr-studio-via-cloudformation-session-mapping-usable."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-emr-studio-via-cloudformation-session-mapping-usable"
GROUP = "deploy"
SERVICES = ["emr"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  StudioName:
    Type: String
  VpcId:
    Type: String
  SubnetId:
    Type: String
  ServiceRoleArn:
    Type: String
  UserRoleArn:
    Type: String
  WorkspaceSecurityGroupId:
    Type: String
  EngineSecurityGroupId:
    Type: String
  DefaultS3Location:
    Type: String
  IdcInstanceArn:
    Type: String
  IdentityName:
    Type: String
  SessionPolicyArn:
    Type: String
Resources:
  Studio:
    Type: AWS::EMR::Studio
    Properties:
      Name: !Ref StudioName
      AuthMode: SSO
      VpcId: !Ref VpcId
      SubnetIds:
        - !Ref SubnetId
      ServiceRole: !Ref ServiceRoleArn
      # AWS::EMR::Studio does not mark UserRole as required in its schema, but real AWS
      # rejects AuthMode SSO with "UserRole is required to create a studio with SSO
      # auth-mode" if it is omitted.
      UserRole: !Ref UserRoleArn
      WorkspaceSecurityGroupId: !Ref WorkspaceSecurityGroupId
      EngineSecurityGroupId: !Ref EngineSecurityGroupId
      DefaultS3Location: !Ref DefaultS3Location
      IdcInstanceArn: !Ref IdcInstanceArn
  Mapping:
    Type: AWS::EMR::StudioSessionMapping
    Properties:
      StudioId: !Ref Studio
      IdentityType: GROUP
      IdentityName: !Ref IdentityName
      SessionPolicyArn: !Ref SessionPolicyArn
Outputs:
  StudioId:
    Value: !Ref Studio
"""


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A CFN-deployed EMR Studio's session mapping is readable/live via GetStudioSessionMapping."""
    idc_arn, identity_store_id = _identity_center_instance(ctx)

    vpc_id, subnet_id = _studio_vpc_and_subnet(ctx)
    ws_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id)
    service_role_arn = _ensure_studio_role(ctx, "sim2real-emr-studio-svc-")
    user_role_arn = _ensure_studio_role(ctx, "sim2real-emr-studio-usr-")
    bucket = _create_bucket(ctx)
    session_policy_arn = _create_session_policy(ctx)
    group_name, group_id = _create_identity_group(ctx, identity_store_id, "sim2real-emr-cfn-group")

    stack_name = ctx.unique_name("sim2real-emr-studio-cfn-")
    outputs = _deploy_stack(
        ctx,
        _TEMPLATE,
        {
            "StudioName": ctx.unique_name("sim2real-emr-studio-"),
            "VpcId": vpc_id,
            "SubnetId": subnet_id,
            "ServiceRoleArn": service_role_arn,
            "UserRoleArn": user_role_arn,
            "WorkspaceSecurityGroupId": ws_sg,
            "EngineSecurityGroupId": engine_sg,
            "DefaultS3Location": f"s3://{bucket}/studio/",
            "IdcInstanceArn": idc_arn,
            "IdentityName": group_name,
            "SessionPolicyArn": session_policy_arn,
        },
        stack_name,
    )
    studio_id = outputs["StudioId"]

    emr = ctx.client("emr")
    mapping = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityName=group_name)[
        "SessionMapping"
    ]
    assert mapping["StudioId"] == studio_id, f"expected StudioId {studio_id!r}, got {mapping['StudioId']!r}"
    assert mapping["IdentityName"] == group_name, (
        f"expected IdentityName {group_name!r}, got {mapping['IdentityName']!r}"
    )
    assert mapping["IdentityId"] == group_id, f"expected IdentityId {group_id!r}, got {mapping['IdentityId']!r}"
    assert mapping["SessionPolicyArn"] == session_policy_arn, (
        f"expected SessionPolicyArn {session_policy_arn!r}, got {mapping['SessionPolicyArn']!r}"
    )


# ===== helpers =====


def _identity_center_instance(ctx) -> tuple[str, str]:
    """Adopt an existing IAM Identity Center instance if this account/region already has
    one; otherwise create it. The instance is an account-global singleton shared with
    whatever else runs concurrently in this account, so a freshly created one is
    deliberately never deleted here -- only this check's own group/mapping are cleaned
    up (see _create_identity_group and the Mapping resource's own lifecycle)."""
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if not instances or "IdentityStoreId" not in instances[0]:
        if not instances:
            sso.create_instance(Name=ctx.unique_name("sim2real-emr-studio-idc-"))
        instances = _poll_until(
            lambda: sso.list_instances().get("Instances", []),
            lambda insts: bool(insts) and "IdentityStoreId" in insts[0],
            timeout_s=120,
            interval_s=5,
        )
    inst = instances[0]
    return inst["InstanceArn"], inst["IdentityStoreId"]


def _create_identity_group(ctx, identity_store_id: str, prefix: str) -> tuple[str, str]:
    identitystore = ctx.client("identitystore")
    name = ctx.unique_name(f"{prefix}-")
    group_id = identitystore.create_group(IdentityStoreId=identity_store_id, DisplayName=name)["GroupId"]
    ctx.on_cleanup(lambda: _delete_group_safe(ctx, identity_store_id, group_id))
    return name, group_id


def _delete_group_safe(ctx, identity_store_id: str, group_id: str) -> None:
    identitystore = ctx.client("identitystore")
    _unless_gone(
        lambda: identitystore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id),
        "ResourceNotFoundException",
    )


def _unless_gone(fn, *gone_codes: str) -> None:
    """Run a teardown call, returning only when it reports the resource already gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone_codes:
            raise


def _studio_vpc_and_subnet(ctx) -> tuple[str, str]:
    """Adopt this account's shared network if it has one; a freshly provisioned account may
    not, so this falls back to creating its own rather than depending on one being
    ambiently present."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
        if subnets:
            return vpc_id, subnets[0]["SubnetId"]

    vpc_id = ec2.create_vpc(CidrBlock="10.93.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_safe(ctx, vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-emr-studio-vpc-")}])
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.93.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet_safe(ctx, subnet_id))
    return vpc_id, subnet_id


def _delete_vpc_safe(ctx, vpc_id: str) -> None:
    ec2 = ctx.client("ec2")
    _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound")


def _delete_subnet_safe(ctx, subnet_id: str) -> None:
    ec2 = ctx.client("ec2")
    _unless_gone(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound")


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


def _ensure_studio_role(ctx, prefix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, role_name, policy_arn))
    _poll_until(
        lambda: {p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]},
        lambda attached: policy_arn in attached,
        timeout_s=30,
        interval_s=3,
    )
    return role_arn


def _poll_until(probe, predicate, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_role_safe(ctx, role_name: str, policy_arn: str) -> None:
    iam = ctx.client("iam")
    _unless_gone(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
                 "NoSuchEntity")
    _unless_gone(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-studio-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint
    # for it and requires the constraint to be omitted, unlike every other region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket_safe(ctx, name))
    return name


def _delete_bucket_safe(ctx, name: str) -> None:
    s3 = ctx.client("s3")

    def _empty() -> None:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")

    _unless_gone(_empty, "NoSuchBucket")
    _unless_gone(lambda: s3.delete_bucket(Bucket=name), "NoSuchBucket")


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
    _unless_gone(lambda: iam.delete_policy(PolicyArn=arn), "NoSuchEntity")


def _deploy_stack(ctx, template_body: str, parameters: dict[str, str], stack_name: str) -> dict[str, str]:
    """Create the stack and wait for CREATE_COMPLETE. ServiceRole/UserRole are roles this
    check just created; IAM role propagation to STS is the one transient failure mode
    here -- if the stack rolls back with a reason naming an authorization failure on the
    role, that is the eventual-consistency window still open, not a real defect -- delete
    the failed stack and retry the identical create under the same name, bounded by an
    overall deadline. A validation error (e.g. a missing required property) names the
    role too but is never transient, so it is not retried."""
    cfn = ctx.client("cloudformation")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    cfn_params = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    deadline = time.monotonic() + 300.0
    while True:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=cfn_params,
            Capabilities=["CAPABILITY_IAM"],
        )
        try:
            cfn.get_waiter("stack_create_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
            )
            break
        except WaiterError as exc:
            stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
            reason = (_stack_failure_reason(cfn, stack_name) or stack.get("StackStatusReason") or "").lower()
            is_role_propagation_lag = "role" in reason and (
                "authoriz" in reason or "assume" in reason or "access denied" in reason
            )
            if is_role_propagation_lag and time.monotonic() < deadline:
                _delete_stack_and_wait(ctx, stack_name)
                continue
            raise AssertionError(
                f"stack {stack_name} did not reach CREATE_COMPLETE: {stack['StackStatus']} ({reason})"
            ) from exc
    resp = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in resp.get("Outputs", [])}


def _stack_failure_reason(cfn, stack_name: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for event in events:
        reason = event.get("ResourceStatusReason")
        if event.get("ResourceStatus") == "CREATE_FAILED" and reason and reason != "Resource creation cancelled":
            return reason
    return ""


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})



def _delete_security_group_when_free(ec2, sg_id, timeout_s=150.0, interval_s=2.0):
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
