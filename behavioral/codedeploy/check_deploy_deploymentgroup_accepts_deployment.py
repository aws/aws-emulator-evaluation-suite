"""deploy-deploymentgroup-accepts-deployment."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-deploymentgroup-accepts-deployment"
GROUP = "server-side"
SERVICES = ["codedeploy"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  AppName:
    Type: String
  RoleArn:
    Type: String
  DGName:
    Type: String
Resources:
  DG:
    Type: AWS::CodeDeploy::DeploymentGroup
    Properties:
      ApplicationName: !Ref AppName
      DeploymentGroupName: !Ref DGName
      ServiceRoleArn: !Ref RoleArn
      DeploymentConfigName: CodeDeployDefault.AllAtOnce
"""

_DEPLOYMENT_CONFIG_NAME = "CodeDeployDefault.AllAtOnce"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DeploymentGroup with an explicit DeploymentConfigName accepts
    CreateDeployment, and GetDeployment reports that configured name rather than the default."""
    codedeploy = ctx.client("codedeploy")

    app_name = ctx.unique_name("sim2real-cdapp-")
    codedeploy.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cd"}],
    )
    ctx.on_cleanup(lambda: codedeploy.delete_application(applicationName=app_name))

    role_arn = _create_codedeploy_service_role(ctx)
    # Give the role's trust/attachment a moment to propagate before CFN uses it.
    _wait_role_assumable(ctx, role_arn)

    dg_name = ctx.unique_name("sim2real-cddg-")
    _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters=[
            {"ParameterKey": "AppName", "ParameterValue": app_name},
            {"ParameterKey": "RoleArn", "ParameterValue": role_arn},
            {"ParameterKey": "DGName", "ParameterValue": dg_name},
        ],
    )

    dg = codedeploy.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)["deploymentGroupInfo"]
    assert dg["deploymentConfigName"] == _DEPLOYMENT_CONFIG_NAME, (
        f"expected the CFN-configured deploymentConfigName {_DEPLOYMENT_CONFIG_NAME!r} on the "
        f"deployment group, got {dg.get('deploymentConfigName')!r}"
    )

    revision = _upload_revision_bundle(ctx)
    deployment_id = codedeploy.create_deployment(
        applicationName=app_name, deploymentGroupName=dg_name, revision=revision
    )["deploymentId"]

    got = codedeploy.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
    assert got["deploymentConfigName"] == _DEPLOYMENT_CONFIG_NAME, (
        f"expected the deployment to inherit the group's deploymentConfigName "
        f"{_DEPLOYMENT_CONFIG_NAME!r} (not the account-wide default), got "
        f"{got.get('deploymentConfigName')!r}"
    )
    assert got["applicationName"] == app_name, (
        f"expected GetDeployment.applicationName {app_name!r}, got {got.get('applicationName')!r}"
    )
    assert got["deploymentGroupName"] == dg_name, (
        f"expected GetDeployment.deploymentGroupName {dg_name!r}, got {got.get('deploymentGroupName')!r}"
    )



def _deploy_cfn(ctx, template_body: str, parameters=None) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cdstack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters or [],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cd"}],
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cd"}],
    )["Role"]["Arn"]
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


def _wait_role_assumable(ctx, role_arn: str, timeout_s: float = 30.0) -> None:
    iam = ctx.client("iam")
    role_name = role_arn.split("/")[-1]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        policies = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        if any(p["PolicyArn"].endswith("AWSCodeDeployRole") for p in policies):
            time.sleep(5)  # small extra buffer for cross-service propagation
            return
        time.sleep(2)


def _upload_revision_bundle(ctx) -> dict:
    import io
    import zipfile

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cdrev-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cd"}]},
    )

    def _cleanup():
        s3.delete_object(Bucket=bucket, Key="revision.zip")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)

    appspec = "version: 0.0\nos: linux\nfiles:\n  - source: /\n    destination: /tmp/sim2real\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("appspec.yml", appspec)
    put_resp = s3.put_object(Bucket=bucket, Key="revision.zip", Body=buf.getvalue())
    etag = put_resp["ETag"].strip('"')
    return {
        "revisionType": "S3",
        "s3Location": {"bucket": bucket, "key": "revision.zip", "bundleType": "zip", "eTag": etag},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
