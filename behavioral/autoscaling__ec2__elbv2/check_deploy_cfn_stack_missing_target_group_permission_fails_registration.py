"""deploy-cfn-stack-missing-target-group-permission-fails-registration."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-missing-target-group-permission-fails-registration"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  VpcId:
    Type: AWS::EC2::VPC::Id
  SubnetIds:
    Type: List<AWS::EC2::Subnet::Id>
  ImageId:
    Type: AWS::EC2::Image::Id
Resources:
  LaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        ImageId: !Ref ImageId
        InstanceType: t3.micro
        TagSpecifications:
          - ResourceType: instance
            Tags:
              - Key: sim2real:managed
                Value: "true"
  TargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      VpcId: !Ref VpcId
      Port: 80
      Protocol: HTTP
      TargetType: instance
  AutoScalingGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      MinSize: "1"
      MaxSize: "1"
      DesiredCapacity: "1"
      VPCZoneIdentifier: !Ref SubnetIds
      LaunchTemplate:
        LaunchTemplateId: !Ref LaunchTemplate
        Version: !GetAtt LaunchTemplate.LatestVersionNumber
      TargetGroupARNs:
        - !Ref TargetGroup
      Tags:
        - Key: sim2real:managed
          Value: "true"
          PropagateAtLaunch: true
Outputs:
  TargetGroupArn:
    Value: !Ref TargetGroup
  AutoScalingGroupName:
    Value: !Ref AutoScalingGroup
"""


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A deployer with no elasticloadbalancing permission cannot create the stack's target group, so
    the stack rolls back with no instance launched; an unrestricted deployer's stack registers
    one."""
    vpc_id, subnet_ids = _get_default_network(ctx)
    ami_id = _get_al2_ami(ctx)
    params = {"VpcId": vpc_id, "SubnetIds": ",".join(subnet_ids), "ImageId": ami_id}

    # --- negative: deploy with a role that can do everything EXCEPT elasticloadbalancing:* ---
    policy_no_elb = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "cloudformation:*",
                    "ec2:*",
                    "autoscaling:*",
                    "iam:PassRole",
                    "iam:CreateServiceLinkedRole",
                ],
                "Resource": "*",
            }
        ],
    }
    _, restricted_arn = _create_restricted_role(ctx, policy_no_elb)
    restricted_cfn = _assume_role_client(ctx, restricted_arn, "cloudformation")

    stack_name = _xname(ctx, "stk-neg")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    restricted_cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": k, "ParameterValue": v} for k, v in params.items()
        ],
        Tags=_xsvc_tags_kv(),
        Capabilities=[],
    )
    final_status = _poll_until(
        lambda: restricted_cfn.describe_stacks(StackName=stack_name)["Stacks"][0][
            "StackStatus"
        ],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=300,
        interval_s=5.0,
        description="restricted-role stack reaches a terminal state",
    )
    assert final_status == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE, got {final_status}"
    )

    # effect-absent: the target group was never created, and no instances were ever launched.
    events = restricted_cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    tg_failure = [
        e
        for e in events
        if e["LogicalResourceId"] == "TargetGroup"
        and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert tg_failure, "expected TargetGroup resource creation to fail"
    reason = tg_failure[0].get("ResourceStatusReason", "")
    assert "not authorized" in reason.lower(), (
        f"expected TargetGroup CREATE_FAILED reason to cite an authorization denial, got: {reason!r}"
    )

    autoscaling = ctx.client("autoscaling")
    groups = autoscaling.describe_auto_scaling_groups(
        Filters=[{"Name": "tag:sim2real:managed", "Values": ["true"]}]
    )["AutoScalingGroups"]
    leaked = [g for g in groups if stack_name in g.get("AutoScalingGroupName", "")]
    assert not leaked, (
        "an ASG from the rolled-back stack should never have been created"
    )

    # --- positive control: identical template, unrestricted identity, succeeds fully ---
    result = _deploy_cfn(
        ctx, _TEMPLATE, parameters=params, capabilities=[], timeout_s=400
    )
    tg_arn = result["outputs"]["TargetGroupArn"]
    asg_name = result["outputs"]["AutoScalingGroupName"]

    elbv2 = ctx.client("elbv2")

    def _in_service_ids():
        gs = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ]
        instances = gs[0]["Instances"] if gs else []
        return [
            i["InstanceId"] for i in instances if i["LifecycleState"] == "InService"
        ]

    instance_ids = _poll_until(
        _in_service_ids,
        lambda ids: len(ids) >= 1,
        timeout_s=400,
        interval_s=10,
        description="positive-control ASG instance reaches InService",
    )

    def _registered_ids():
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn)[
            "TargetHealthDescriptions"
        ]
        return [t["Target"]["Id"] for t in health]

    registered = _poll_until(
        _registered_ids,
        lambda ids: set(instance_ids).issubset(set(ids)),
        timeout_s=180,
        interval_s=10,
        description="positive-control instances register with target group",
    )
    assert set(instance_ids).issubset(set(registered)), (
        f"expected positive-control instances {sorted(instance_ids)} to be registered with "
        f"{tg_arn}, got registered targets {sorted(registered)}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=900,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _create_restricted_role(ctx, policy_document: dict) -> tuple[str, str]:
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-xsvc-restricted-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=_xsvc_tags_kv(),
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="restricted-policy",
        PolicyDocument=json.dumps(policy_document),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="restricted-policy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


def _assume_role_client(ctx, role_arn: str, service: str):
    sts = ctx.client("sts")

    def _try():
        try:
            return sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-restricted"
            )["Credentials"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                return None
            raise

    creds = _poll_until(
        _try,
        lambda c: c is not None,
        timeout_s=60,
        interval_s=3,
        description="assume restricted role",
    )
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _get_default_network(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to launch test EC2 instances"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if len(subnets) < 2:
        raise AssertionError("shared network has fewer than 2 subnets available")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    return vpc_id, subnet_ids


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
