"""batch-get-deployment-targets-reflects-instances."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-get-deployment-targets-reflects-instances"
GROUP = "data-plane"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a deployment resolves its targets, the target ids surfaced by
    ListDeploymentTargets / BatchGetDeploymentTargets match the instances reported by
    ListDeploymentInstances."""
    cd = ctx.client("codedeploy")

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="app.zip", Body=b"sim2real-codedeploy-fixture-bytes")

    instance_name = ctx.unique_name("sim2real-cdonprem-")
    cd.register_on_premises_instance(
        instanceName=instance_name,
        iamUserArn=f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:user/{ctx.unique_name('sim2real-cduser-')}",
    )
    ctx.on_cleanup(lambda: _deregister_safe(cd, instance_name))

    tag_value = ctx.unique_name("sim2real-cdtagval-")
    cd.add_tags_to_on_premises_instances(
        tags=[{"Key": "sim2real-target", "Value": tag_value}], instanceNames=[instance_name]
    )

    role_arn = _create_service_role(ctx)

    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    dg_name = ctx.unique_name("sim2real-cddg-")
    _create_deployment_group_with_role_retry(
        ctx,
        cd,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
        onPremisesInstanceTagFilters=[
            {"Key": "sim2real-target", "Value": tag_value, "Type": "KEY_AND_VALUE"}
        ],
    )

    deployment_id = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=dg_name,
        revision={"revisionType": "S3", "s3Location": {"bucket": bucket, "key": "app.zip", "bundleType": "zip"}},
    )["deploymentId"]
    ctx.on_cleanup(lambda: _stop_deployment_safe(cd, deployment_id))

    target_ids = _poll_until(
        lambda: _try_list_targets(cd, deployment_id),
        lambda ids: bool(ids),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert instance_name in target_ids, f"expected {instance_name!r} among targets {target_ids}"

    batch = cd.batch_get_deployment_targets(deploymentId=deployment_id, targetIds=target_ids)
    batch_ids = {t["instanceTarget"]["targetId"] for t in batch["deploymentTargets"]}
    assert batch_ids == set(target_ids), f"expected batch ids {set(target_ids)!r}, got {batch_ids!r}"

    instances = cd.list_deployment_instances(deploymentId=deployment_id)["instancesList"]
    assert instance_name in instances, f"expected {instance_name!r} in instances {instances!r}"
    assert set(instances) == set(target_ids), (
        f"expected list_deployment_instances {set(instances)!r} to match target ids {set(target_ids)!r}"
    )


# ===== helpers =====
def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cdbkt-").lower()
    if ctx.region == "us-east-1":
        # S3 rejects an explicit LocationConstraint of us-east-1; omit it there only.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_deployment_group_with_role_retry(ctx, cd, **kwargs):
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return cd.create_deployment_group(**kwargs)
        except cd.exceptions.InvalidRoleException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _try_list_targets(cd, deployment_id: str) -> list[str]:
    try:
        return cd.list_deployment_targets(deploymentId=deployment_id)["targetIds"]
    except cd.exceptions.DeploymentNotStartedException:
        return []


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never became true, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _deregister_safe(cd, instance_name: str) -> None:
    try:
        cd.deregister_on_premises_instance(instanceName=instance_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InstanceNotRegisteredException":
            raise


def _stop_deployment_safe(cd, deployment_id: str) -> None:
    try:
        cd.stop_deployment(deploymentId=deployment_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DeploymentAlreadyCompletedException",
            "DeploymentDoesNotExistException",
            "DeploymentGroupDoesNotExistException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
