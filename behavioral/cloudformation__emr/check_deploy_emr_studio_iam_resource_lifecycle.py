"""deploy-emr-studio-iam-resource-lifecycle."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-emr-studio-iam-resource-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "emr"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

_STUDIO_GONE = (
    "InvalidRequestException",
    "Studio does not exist. (Service: AWSEditors; Status Code: 400; Error Code: "
    "InvalidRequestException; Request ID: <id>; Proxy: null)",
)
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
  WorkspaceSecurityGroupId:
    Type: String
  EngineSecurityGroupId:
    Type: String
  DefaultS3Location:
    Type: String
Resources:
  Studio:
    Type: AWS::EMR::Studio
    Properties:
      Name: !Ref StudioName
      AuthMode: IAM
      VpcId: !Ref VpcId
      SubnetIds:
        - !Ref SubnetId
      ServiceRole: !Ref ServiceRoleArn
      WorkspaceSecurityGroupId: !Ref WorkspaceSecurityGroupId
      EngineSecurityGroupId: !Ref EngineSecurityGroupId
      DefaultS3Location: !Ref DefaultS3Location
Outputs:
  StudioId:
    Value: !Ref Studio
  StudioArn:
    Value: !GetAtt Studio.Arn
  StudioUrl:
    Value: !GetAtt Studio.Url
"""


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::EMR::Studio is a real, describable EMR studio whose Ref and
    GetAtt attributes match EMR's own values, and deleting the stack deletes the studio."""
    vpc_id, subnet_id = _studio_vpc_and_subnet(ctx)
    ws_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id)
    bucket = _create_bucket(ctx)
    service_role_arn = _ensure_studio_role(ctx, bucket)
    studio_name = ctx.unique_name("sim2real-emr-studio-")
    default_location = f"s3://{bucket}/studio/"

    stack_name = ctx.unique_name("sim2real-emr-studio-cfn-")
    cfn = ctx.client("cloudformation")
    stack_id, outputs = _deploy_stack(
        ctx,
        cfn,
        _TEMPLATE,
        {
            "StudioName": studio_name,
            "VpcId": vpc_id,
            "SubnetId": subnet_id,
            "ServiceRoleArn": service_role_arn,
            "WorkspaceSecurityGroupId": ws_sg,
            "EngineSecurityGroupId": engine_sg,
            "DefaultS3Location": default_location,
        },
        stack_name,
    )
    studio_id = outputs["StudioId"]

    emr = ctx.client("emr")
    # Ref against an independent read: ListStudios by the declared name.
    listed = [x["StudioId"] for x in paginate(emr, "list_studios", "Studios")
              if x["Name"] == studio_name]
    assert listed == [studio_id], f"ListStudios lists {listed!r}, Ref is {studio_id!r}"
    described = emr.describe_studio(StudioId=studio_id)["Studio"]
    assert described["StudioId"] == studio_id, (
        f"Ref {studio_id!r} does not match DescribeStudio's StudioId {described['StudioId']!r}"
    )
    assert described["StudioArn"] == outputs["StudioArn"], (
        f"GetAtt Arn {outputs['StudioArn']!r} does not match DescribeStudio's StudioArn {described['StudioArn']!r}"
    )
    assert described["Url"] == outputs["StudioUrl"], (
        f"GetAtt Url {outputs['StudioUrl']!r} does not match DescribeStudio's Url {described['Url']!r}"
    )
    assert described["Name"] == studio_name, (
        f"expected Name {studio_name!r}, got {described['Name']!r}"
    )
    assert described["DefaultS3Location"] == default_location, (
        f"expected DefaultS3Location {default_location!r}, got {described['DefaultS3Location']!r}"
    )
    assert described["AuthMode"] == "IAM", f"expected AuthMode IAM, got {described['AuthMode']!r}"
    assert described["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {described['VpcId']!r}"
    assert described["SubnetIds"] == [subnet_id], (
        f"expected SubnetIds {[subnet_id]!r}, got {described['SubnetIds']!r}"
    )
    assert described["ServiceRole"] == service_role_arn, (
        f"expected ServiceRole {service_role_arn!r}, got {described['ServiceRole']!r}"
    )
    assert described["WorkspaceSecurityGroupId"] == ws_sg, (
        f"expected WorkspaceSecurityGroupId {ws_sg!r}, got {described['WorkspaceSecurityGroupId']!r}"
    )
    assert described["EngineSecurityGroupId"] == engine_sg, (
        f"expected EngineSecurityGroupId {engine_sg!r}, got {described['EngineSecurityGroupId']!r}"
    )

    delete_stack(cfn, stack_id)

    got = _refusal(lambda: emr.describe_studio(StudioId=studio_id), ctx.account)
    assert got == _STUDIO_GONE, f"DescribeStudio after the stack delete: {got!r}"


# ===== helpers =====


def _refusal(fn, account):
    """(Error.Code, Error.Message masked) of the ClientError fn() raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), masked(err.get("Message") or "", account)
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _unless_gone(fn, *gone_codes: str) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone_codes:
            raise


def _studio_vpc_and_subnet(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.94.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.94.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"))
    return vpc_id, subnet_id


def _create_studio_security_groups(ctx, vpc_id: str) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-ws-"),
        Description="sim2real EMR studio workspace sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, ws_sg))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-eng-"),
        Description="sim2real EMR studio engine sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, engine_sg))
    ec2.authorize_security_group_ingress(
        GroupId=engine_sg, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": ws_sg}]}]
    )
    return ws_sg, engine_sg


def _delete_security_group_when_free(ec2, sg_id: str, timeout_s: float = 150.0, interval_s: float = 2.0) -> None:
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


_ROLE_POLICY_NAME = "studio-default-location"


def _ensure_studio_role(ctx, bucket: str) -> str:
    """A studio service role EMR may assume only for this account, scoped to the studio's bucket."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-svc-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
                }
            ],
        }
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust,
                               Tags=[{"Key": "sim2real", "Value": role_name}])["Role"]["Arn"]
    partition = role_arn.split(":")[1]
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": f"arn:{partition}:s3:::{bucket}/*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket", "s3:GetBucketLocation", "s3:GetEncryptionConfiguration",
                    ],
                    "Resource": f"arn:{partition}:s3:::{bucket}",
                },
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=_ROLE_POLICY_NAME, PolicyDocument=policy)
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    _unless_gone(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_ROLE_POLICY_NAME), "NoSuchEntity")
    _unless_gone(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-studio-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": name}]})
    return name


def _delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")

    def _empty() -> None:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")

    _unless_gone(_empty, "NoSuchBucket")
    _unless_gone(lambda: s3.delete_bucket(Bucket=name), "NoSuchBucket")


def _deploy_stack(ctx, cfn, template_body: str, parameters: dict[str, str],
                  stack_name: str) -> tuple[str, dict[str, str]]:
    """Create the stack and wait for CREATE_COMPLETE, retrying a role-propagation rollback
    (IAM's eventual consistency with STS, not a real defect) under an overall deadline."""
    cfn_params = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    deadline = time.monotonic() + 300.0
    while True:
        stack_id = create_stack(ctx, cfn, stack_name, template_body, Parameters=cfn_params)
        status = wait_stack(cfn, stack_id, timeout_s=600.0)
        if status == "CREATE_COMPLETE":
            return stack_id, stack_outputs(cfn, stack_id)
        reason = _stack_failure_reason(cfn, stack_id).lower()
        # A just-written inline policy is not yet visible to EMR's S3 access validation.
        is_role_propagation_lag = "role" in reason and (
            "authoriz" in reason or "assume" in reason or "access denied" in reason
            or "'servicerole' does not have permission to access the 's3 location'" in reason
        )
        if is_role_propagation_lag and time.monotonic() < deadline:
            delete_stack(cfn, stack_id)
            continue
        raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE: {status} ({reason})")


def _stack_failure_reason(cfn, stack_id: str) -> str:
    for event in stack_events(cfn, stack_id):
        reason = event.get("ResourceStatusReason")
        if event.get("ResourceStatus") == "CREATE_FAILED" and reason and reason != "Resource creation cancelled":
            return reason
    return ""


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
