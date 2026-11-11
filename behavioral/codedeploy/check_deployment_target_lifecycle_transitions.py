"""deployment-target-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-target-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDeploymentTarget/ListDeploymentTargets transition from unavailable
    (DeploymentNotStartedException) to populated once the deployment progresses to
    enumerate its target instance, which leaves Pending for InProgress once dispatched."""
    cd = ctx.client("codedeploy")
    setup = _create_onprem_deployment_setup(ctx, "cdtargetlifecycle", instance_count=1)
    instance_name = setup["instance_names"][0]

    deployment_id = cd.create_deployment(
        applicationName=setup["app_name"],
        deploymentGroupName=setup["dg_name"],
        revision={"revisionType": "S3", "s3Location": setup["revision"]},
    )["deploymentId"]
    ctx.on_cleanup(lambda: _stop_deployment(cd, deployment_id))

    def probe():
        try:
            return cd.list_deployment_targets(deploymentId=deployment_id)["targetIds"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "DeploymentNotStartedException":
                return []
            raise

    target_ids = _poll_until(probe, lambda ids: len(ids) > 0, timeout_s=120.0, interval_s=3.0)
    assert instance_name in target_ids, (
        f"expected {instance_name!r} among targets, got {target_ids!r}"
    )

    # A target can be listed while still Pending, before CodeDeploy dispatches to it.
    target = _poll_until(
        lambda: cd.get_deployment_target(
            deploymentId=deployment_id, targetId=instance_name
        )["deploymentTarget"],
        lambda t: (t.get("instanceTarget") or {}).get("status") != "Pending",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert target["deploymentTargetType"] == "InstanceTarget", (
        f"expected InstanceTarget, got {target['deploymentTargetType']!r}"
    )
    instance_target = target["instanceTarget"]
    assert instance_target["targetId"] == instance_name, (
        f"expected targetId {instance_name!r}, got {instance_target['targetId']!r}"
    )
    assert instance_target["status"] == "InProgress", (
        f"expected InProgress (target is enumerated as soon as codedeploy dispatches to "
        f"it, before any on-premises agent ever polls), got {instance_target['status']!r}"
    )


def _stop_deployment(cd, deployment_id):
    """Stop the deployment this check started; one that already finished needs nothing."""
    try:
        cd.stop_deployment(deploymentId=deployment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DeploymentAlreadyCompletedException":
            raise


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
    assert last_err is not None
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
