"""deployment-create-get-list-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-create-get-list-lifecycle"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeployment produces a deployment visible via GetDeployment and enumerated
    by ListDeployments scoped to its application/group."""
    cd = ctx.client("codedeploy")
    setup = _create_onprem_deployment_setup(ctx, "cdglifecycle")

    deployment_id = cd.create_deployment(
        applicationName=setup["app_name"],
        deploymentGroupName=setup["dg_name"],
        revision={"revisionType": "S3", "s3Location": setup["revision"]},
    )["deploymentId"]

    info = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
    assert info["applicationName"] == setup["app_name"], (
        f"expected applicationName {setup['app_name']!r}, got {info['applicationName']!r}"
    )
    assert info["deploymentGroupName"] == setup["dg_name"], (
        f"expected deploymentGroupName {setup['dg_name']!r}, got {info['deploymentGroupName']!r}"
    )
    assert info["revision"]["s3Location"]["bucket"] == setup["revision"]["bucket"], (
        f"expected revision bucket {setup['revision']['bucket']!r}, "
        f"got {info['revision']['s3Location']['bucket']!r}"
    )
    assert info["revision"]["s3Location"]["key"] == setup["revision"]["key"], (
        f"expected revision key {setup['revision']['key']!r}, got {info['revision']['s3Location']['key']!r}"
    )
    assert info["status"] in {
        "Created",
        "Queued",
        "InProgress",
        "Ready",
        "Succeeded",
        "Failed",
        "Stopped",
    }, f"unexpected deployment status {info['status']!r}"

    ids = _list_all_deployments(cd, applicationName=setup["app_name"], deploymentGroupName=setup["dg_name"])
    assert deployment_id in ids, f"deployment {deployment_id!r} missing from ListDeployments {ids!r}"


def _create_codedeploy_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codedeploy.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
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


def _create_deployment_group_with_retry(cd, **kwargs):
    deadline = time.monotonic() + 60.0
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return cd.create_deployment_group(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException":
                last_err = e
                time.sleep(3)
                continue
            raise
    assert last_err is not None, "retry loop exited without ever calling create_deployment_group"
    raise last_err


def _create_s3_revision(ctx) -> dict:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cdrev-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "app.zip"
    body = b"PK\x05\x06" + bytes(18)
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return {"bucket": bucket, "key": key, "bundleType": "zip"}


def _register_onprem_instance(ctx, tag_value: str, suffix: str = "") -> str:
    iam = ctx.client("iam")
    cd = ctx.client("codedeploy")
    user_name = ctx.unique_name(f"sim2real-cdonprem-user{suffix}-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    instance_name = ctx.unique_name(f"sim2real-onprem{suffix}-")
    cd.register_on_premises_instance(instanceName=instance_name, iamUserArn=user_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=instance_name))
    cd.add_tags_to_on_premises_instances(
        tags=[{"Key": "sim2real-tag", "Value": tag_value}], instanceNames=[instance_name]
    )
    return instance_name


def _create_onprem_deployment_setup(ctx, tag_value: str, instance_count: int = 1) -> dict:
    cd = ctx.client("codedeploy")
    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    role_arn = _create_codedeploy_service_role(ctx)

    instance_names = [
        _register_onprem_instance(ctx, tag_value, suffix=f"-{i}") for i in range(instance_count)
    ]

    dg_name = ctx.unique_name("sim2real-cdgroup-")
    _create_deployment_group_with_retry(
        cd,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
        onPremisesInstanceTagFilters=[{"Key": "sim2real-tag", "Value": tag_value, "Type": "KEY_AND_VALUE"}],
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name))

    revision = _create_s3_revision(ctx)
    return {
        "app_name": app_name,
        "dg_name": dg_name,
        "revision": revision,
        "instance_names": instance_names,
    }


def _list_all_deployments(cd, **kwargs) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = cd.list_deployments(**params)
        ids.extend(resp.get("deployments", []))
        token = resp.get("nextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
