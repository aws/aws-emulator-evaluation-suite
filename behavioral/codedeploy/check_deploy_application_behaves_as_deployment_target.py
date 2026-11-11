"""deploy-application-behaves-as-deployment-target."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-application-behaves-as-deployment-target"
GROUP = "state-machine"
SERVICES = ["codedeploy"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  AppName:
    Type: String
Resources:
  App:
    Type: AWS::CodeDeploy::Application
    Properties:
      ApplicationName: !Ref AppName
      ComputePlatform: Server
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CodeDeploy Application created purely via CloudFormation is a fully live
    data-plane resource: GetApplication/ListApplications reflect it, and the data
    plane can create a real deployment group underneath it."""
    codedeploy = ctx.client("codedeploy")
    app_name = ctx.unique_name("sim2real-cfnapp-")

    _deploy_cfn(ctx, _TEMPLATE, parameters=[{"ParameterKey": "AppName", "ParameterValue": app_name}])

    got = codedeploy.get_application(applicationName=app_name)["application"]
    assert got["applicationName"] == app_name, f"expected applicationName {app_name!r}, got {got['applicationName']!r}"
    assert got["computePlatform"] == "Server", f"expected computePlatform 'Server', got {got['computePlatform']!r}"

    paginator = codedeploy.get_paginator("list_applications")
    found = False
    for page in paginator.paginate():
        if app_name in page["applications"]:
            found = True
            break
    assert found, "CFN-created application did not appear in ListApplications"

    role_arn = _create_codedeploy_service_role(ctx)
    dg_name = ctx.unique_name("sim2real-cddg-")
    _create_deployment_group_with_retry(
        codedeploy,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
    )
    ctx.on_cleanup(lambda: codedeploy.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name))

    dg = codedeploy.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)["deploymentGroupInfo"]
    assert dg["deploymentGroupName"] == dg_name, f"expected deploymentGroupName {dg_name!r}, got {dg['deploymentGroupName']!r}"
    assert dg["applicationName"] == app_name, f"expected applicationName {app_name!r}, got {dg['applicationName']!r}"

    dg_groups = codedeploy.list_deployment_groups(applicationName=app_name)["deploymentGroups"]
    assert dg_name in dg_groups, f"{dg_name!r} not in list_deployment_groups output: {dg_groups!r}"


def _deploy_cfn(ctx, template_body: str, parameters=None) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cdstack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters or [],
        Capabilities=["CAPABILITY_IAM"],
    )

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return stack_name


def _create_codedeploy_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_deployment_group_with_retry(codedeploy, *, timeout_s=45.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return codedeploy.create_deployment_group(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
