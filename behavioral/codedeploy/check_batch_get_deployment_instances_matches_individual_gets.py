"""batch-get-deployment-instances-matches-individual-gets."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-deployment-instances-matches-individual-gets"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetDeploymentInstances aggregation is consistent with individual
    GetDeploymentInstance results for the same deployment (deprecated EC2/On-premises
    instance-level API)."""
    cd = ctx.client("codedeploy")
    setup = _create_onprem_deployment_setup(ctx, "cdbatchinstances", instance_count=2)

    deployment_id = cd.create_deployment(
        applicationName=setup["app_name"],
        deploymentGroupName=setup["dg_name"],
        revision={"revisionType": "S3", "s3Location": setup["revision"]},
    )["deploymentId"]

    def probe():
        try:
            return cd.list_deployment_instances(deploymentId=deployment_id)["instancesList"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "DeploymentNotStartedException":
                return []
            raise

    instances = _poll_until(probe, lambda ids: len(ids) >= 2, timeout_s=150.0, interval_s=3.0)
    assert set(setup["instance_names"]) <= set(instances), (
        f"expected {setup['instance_names']} to appear in list_deployment_instances, got {instances}"
    )

    batch = cd.batch_get_deployment_instances(deploymentId=deployment_id, instanceIds=setup["instance_names"])
    assert len(batch["instancesSummary"]) == len(setup["instance_names"]), (
        f"expected {len(setup['instance_names'])} batch entries, got {len(batch['instancesSummary'])}"
    )
    # The deprecated InstanceSummary.instanceId may come back ARN-wrapped rather than
    # as the raw on-premises instance name we registered, so match by containment.
    remaining = list(batch["instancesSummary"])
    for instance_id in setup["instance_names"]:
        match = next((s for s in remaining if instance_id in s["instanceId"]), None)
        assert match is not None, f"no batch entry for {instance_id} (got {[s['instanceId'] for s in batch['instancesSummary']]})"
        remaining.remove(match)

        individual = cd.get_deployment_instance(deploymentId=deployment_id, instanceId=instance_id)["instanceSummary"]
        assert match["deploymentId"] == individual["deploymentId"], (
            f"batch deploymentId {match['deploymentId']!r} != individual deploymentId {individual['deploymentId']!r}"
        )
        assert match["instanceId"] == individual["instanceId"], (
            f"batch instanceId {match['instanceId']!r} != individual instanceId {individual['instanceId']!r}"
        )


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
    assert last_err is not None, "create_deployment_group retry loop exited with no error captured"
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
