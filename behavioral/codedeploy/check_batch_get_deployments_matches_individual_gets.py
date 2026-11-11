"""batch-get-deployments-matches-individual-gets."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-deployments-matches-individual-gets"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetDeployments returns entries matching individual GetDeployment calls for
    the same deployment IDs."""
    cd = ctx.client("codedeploy")
    # Use two independent deployment groups (rather than sequential deployments to the
    # same group) since only one deployment may be InProgress per group at a time and
    # these on-premises instances never check in to reach a terminal state promptly.
    setup_a = _create_onprem_deployment_setup(ctx, "cdbatchdeployments-a", instance_count=1)
    setup_b = _create_onprem_deployment_setup(ctx, "cdbatchdeployments-b", instance_count=1)

    deployment_ids = [
        cd.create_deployment(
            applicationName=setup_a["app_name"],
            deploymentGroupName=setup_a["dg_name"],
            revision={"revisionType": "S3", "s3Location": setup_a["revision"]},
        )["deploymentId"],
        cd.create_deployment(
            applicationName=setup_b["app_name"],
            deploymentGroupName=setup_b["dg_name"],
            revision={"revisionType": "S3", "s3Location": setup_b["revision"]},
        )["deploymentId"],
    ]
    assert deployment_ids[0] != deployment_ids[1], (
        f"two independent CreateDeployment calls returned the same deploymentId: {deployment_ids[0]!r}"
    )

    batch = cd.batch_get_deployments(deploymentIds=deployment_ids)
    batch_by_id = {info["deploymentId"]: info for info in batch["deploymentsInfo"]}
    assert set(batch_by_id.keys()) == set(deployment_ids), (
        f"BatchGetDeployments returned {sorted(batch_by_id.keys())}, expected {sorted(deployment_ids)}"
    )

    for deployment_id in deployment_ids:
        individual = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
        batch_entry = batch_by_id[deployment_id]
        assert batch_entry["applicationName"] == individual["applicationName"], (
            f"{deployment_id}: batch applicationName {batch_entry['applicationName']!r} != "
            f"individual {individual['applicationName']!r}"
        )
        assert batch_entry["deploymentGroupName"] == individual["deploymentGroupName"], (
            f"{deployment_id}: batch deploymentGroupName {batch_entry['deploymentGroupName']!r} != "
            f"individual {individual['deploymentGroupName']!r}"
        )
        assert (
            batch_entry["revision"]["s3Location"]["bucket"] == individual["revision"]["s3Location"]["bucket"]
        ), (
            f"{deployment_id}: batch revision bucket {batch_entry['revision']['s3Location']['bucket']!r} != "
            f"individual {individual['revision']['s3Location']['bucket']!r}"
        )
        assert (
            batch_entry["revision"]["s3Location"]["key"] == individual["revision"]["s3Location"]["key"]
        ), (
            f"{deployment_id}: batch revision key {batch_entry['revision']['s3Location']['key']!r} != "
            f"individual {individual['revision']['s3Location']['key']!r}"
        )


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
    assert last_err is not None, "retry loop exited without a create_deployment_group attempt"
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
