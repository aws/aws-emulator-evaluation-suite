"""e2e-on-premises-instance-tag-and-deploy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-on-premises-instance-tag-and-deploy"
GROUP = "e2e"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag-filtered deployment group targets only the tagged on-premises instance; after
    deregister it is unlisted and Get and AddTags both raise InstanceNotRegisteredException."""
    cd = ctx.client("codedeploy")
    sts = ctx.client("sts")

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="app.zip", Body=b"sim2real-codedeploy-onprem-fixture")

    account_id = sts.get_caller_identity()["Account"]
    instance_name, mark_instance_deregistered = _register_instance(ctx, cd, account_id)
    control_name, _ = _register_instance(ctx, cd, account_id)

    tag_value = ctx.unique_name("sim2real-cdtagval-")
    cd.add_tags_to_on_premises_instances(
        tags=[{"Key": "sim2real-fleet", "Value": tag_value}], instanceNames=[instance_name]
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
        onPremisesInstanceTagFilters=[{"Key": "sim2real-fleet", "Value": tag_value, "Type": "KEY_AND_VALUE"}],
    )

    deployment_id = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=dg_name,
        revision={"revisionType": "S3", "s3Location": {"bucket": bucket, "key": "app.zip", "bundleType": "zip"}},
    )["deploymentId"]
    ctx.on_cleanup(lambda: _stop_deployment_safe(cd, deployment_id))

    instances = _poll_until(
        lambda: _try_list_instances(cd, deployment_id),
        lambda ids: bool(ids),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert instance_name in instances, f"expected tagged {instance_name!r} among deployment instances {instances}"
    assert control_name not in instances, (
        f"untagged control {control_name!r} must not be selected by the tag filter, got {instances}"
    )

    cd.deregister_on_premises_instance(instanceName=instance_name)
    mark_instance_deregistered()

    all_names = cd.list_on_premises_instances()["instanceNames"]
    assert instance_name not in all_names, f"{instance_name!r} still listed after deregister: {all_names}"

    try:
        cd.get_on_premises_instance(instanceName=instance_name)
        raise AssertionError(f"expected InstanceNotRegisteredException reading deregistered {instance_name!r}")
    except cd.exceptions.InstanceNotRegisteredException as exc:
        message = exc.response["Error"].get("Message")
        expected = f"The requested host does not exist. Host: {instance_name}"
        assert message == expected, f"GetOnPremisesInstance must say {expected!r}, got {message!r}"

    try:
        cd.add_tags_to_on_premises_instances(
            tags=[{"Key": "sim2real-fleet", "Value": tag_value}], instanceNames=[instance_name]
        )
        raise AssertionError(f"expected mutation against deregistered {instance_name!r} to fail")
    except cd.exceptions.InstanceNotRegisteredException as exc:
        message = exc.response["Error"].get("Message")
        expected = f"Host {instance_name} is not registered"
        assert message == expected, f"AddTagsToOnPremisesInstances must say {expected!r}, got {message!r}"


def _register_instance(ctx, cd, account_id: str):
    name = ctx.unique_name("sim2real-cdonprem-")
    cd.register_on_premises_instance(
        instanceName=name,
        iamUserArn=f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cduser-')}",
    )
    state = {"deregistered": False}
    ctx.on_cleanup(lambda: None if state["deregistered"] else cd.deregister_on_premises_instance(instanceName=name))

    def _mark_deregistered() -> None:
        state["deregistered"] = True

    return name, _mark_deregistered


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cdbkt-").lower()
    if ctx.region == "us-east-1":
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


def _try_list_instances(cd, deployment_id: str) -> list[str]:
    try:
        return cd.list_deployment_instances(deploymentId=deployment_id)["instancesList"]
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
