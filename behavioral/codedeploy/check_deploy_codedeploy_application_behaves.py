"""deploy-codedeploy-application-behaves."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-codedeploy-application-behaves"
GROUP = "deploy"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CodeDeploy Application and DeploymentGroup deployed via a CloudFormation stack
    actually accept and process a real CreateDeployment through to a terminal
    GetDeployment status, not merely reaching CREATE_COMPLETE."""
    cd = ctx.client("codedeploy")

    app_name = ctx.unique_name("sim2real-cdapp-")
    dg_name = ctx.unique_name("sim2real-cddg-")
    role_name = ctx.unique_name("sim2real-cdrole-")
    tag_value = ctx.unique_name("sim2real-no-match-")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "CDRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "codedeploy.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
                        ],
                    },
                },
                "CDApp": {
                    "Type": "AWS::CodeDeploy::Application",
                    "Properties": {"ApplicationName": app_name, "ComputePlatform": "Server"},
                },
                "CDDeploymentGroup": {
                    "Type": "AWS::CodeDeploy::DeploymentGroup",
                    "DependsOn": ["CDRole", "CDApp"],
                    "Properties": {
                        "ApplicationName": {"Ref": "CDApp"},
                        "DeploymentGroupName": dg_name,
                        "ServiceRoleArn": {"Fn::GetAtt": ["CDRole", "Arn"]},
                        "Ec2TagFilters": [
                            {"Key": "sim2real-unmatched-tag", "Value": tag_value, "Type": "KEY_AND_VALUE"}
                        ],
                    },
                },
            },
            "Outputs": {
                "ApplicationName": {"Value": {"Ref": "CDApp"}},
                "DeploymentGroupName": {"Value": {"Ref": "CDDeploymentGroup"}},
            },
        }
    )

    outputs = _deploy_cfn(ctx, template)
    assert outputs["ApplicationName"] == app_name, (
        f"expected CFN output ApplicationName={app_name!r}, got {outputs.get('ApplicationName')!r}"
    )
    assert outputs["DeploymentGroupName"] == dg_name, (
        f"expected CFN output DeploymentGroupName={dg_name!r}, got {outputs.get('DeploymentGroupName')!r}"
    )

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="app.zip", Body=b"sim2real-codedeploy-cfn-fixture")

    deployment_id = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=dg_name,
        revision={"revisionType": "S3", "s3Location": {"bucket": bucket, "key": "app.zip", "bundleType": "zip"}},
    )["deploymentId"]

    deployment_info = _poll_until(
        lambda: cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"],
        lambda info: info["status"] in ("Succeeded", "Failed", "Stopped"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert deployment_info["status"] == "Failed", (
        f"expected deployment {deployment_id} to reach terminal status Failed "
        f"(no instance matches the Ec2TagFilters), got {deployment_info['status']!r}"
    )
    assert deployment_info["errorInformation"]["code"] == "NO_INSTANCES", (
        f"expected errorInformation.code=NO_INSTANCES for a zero-match deployment group, "
        f"got {deployment_info.get('errorInformation')!r}"
    )

    groups = cd.list_deployment_groups(applicationName=app_name)["deploymentGroups"]
    assert dg_name in groups, (
        f"expected CFN-created deployment group {dg_name!r} to appear in "
        f"list_deployment_groups for {app_name!r}, got {groups!r}"
    )


def _deploy_cfn(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cdstack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cdbkt-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never became true, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
