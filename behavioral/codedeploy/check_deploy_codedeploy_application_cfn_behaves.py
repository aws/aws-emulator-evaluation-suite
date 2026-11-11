"""deploy-codedeploy-application-cfn-behaves."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codedeploy-application-cfn-behaves"
GROUP = "deploy"
SERVICES = ["codedeploy"]

_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "CDApplication": {
            "Type": "AWS::CodeDeploy::Application",
            "Properties": {"ComputePlatform": "Server"},
        }
    },
    "Outputs": {
        "ApplicationName": {"Value": {"Ref": "CDApplication"}},
    },
}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-created AWS::CodeDeploy::Application is readable via GetApplication and
    accepts a CreateDeployment on a group built on it that runs to its terminal status."""
    cfn = ctx.client("cloudformation")
    cd = ctx.client("codedeploy")

    stack_name = ctx.unique_name("sim2real-cd-appstack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(_TEMPLATE))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    app_name = outputs["ApplicationName"]

    got = cd.get_application(applicationName=app_name)["application"]
    assert got["applicationName"] == app_name, got
    assert got["computePlatform"] == "Server", got["computePlatform"]

    role_arn = _create_service_role(ctx)
    group = ctx.unique_name("sim2real-cd-dg-")
    _create_deployment_group(
        ctx, cd, app_name, group, role_arn,
        onPremisesInstanceTagFilters=[
            {"Key": ctx.unique_name("sim2real-nomatch-"), "Value": "none", "Type": "KEY_AND_VALUE"}
        ],
    )
    revision = _upload_s3_revision(ctx)
    deployment_id = cd.create_deployment(
        applicationName=app_name, deploymentGroupName=group, revision=revision["location"]
    )["deploymentId"]

    status = _poll_deployment_status(cd, deployment_id, {"Succeeded", "Failed", "Stopped"})
    assert status == "Failed", f"expected Failed for a zero-instance deployment group, got {status}"
    deployed = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
    assert deployed["applicationName"] == app_name, deployed
    assert deployed["status"] == "Failed", deployed["status"]
    assert deployed["errorInformation"]["code"] == "NO_INSTANCES", deployed.get("errorInformation")

    listed = cd.list_deployment_groups(applicationName=app_name)["deploymentGroups"]
    assert group in listed, listed



def _delete_stack(cfn, stack_name):
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _create_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_deployment_group(ctx, cd, application_name, deployment_group_name, service_role_arn, **kwargs):
    deadline = time.monotonic() + 30
    while True:
        try:
            resp = cd.create_deployment_group(
                applicationName=application_name,
                deploymentGroupName=deployment_group_name,
                serviceRoleArn=service_role_arn,
                **kwargs,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: cd.delete_deployment_group(
        applicationName=application_name, deploymentGroupName=deployment_group_name
    ))
    return resp


def _poll_deployment_status(cd, deployment_id, target_statuses, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["status"]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"deployment {deployment_id} did not reach {target_statuses} within {timeout_s}s (last={status})"
    )


def _minimal_zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("appspec.yml", "version: 0.0\nos: linux\nfiles: []\n")
    return buf.getvalue()


def _upload_s3_revision(ctx, key="revision.zip"):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cd-rev-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return {
        "bucket": bucket,
        "key": key,
        "location": {"revisionType": "S3", "s3Location": {"bucket": bucket, "key": key, "bundleType": "zip"}},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
