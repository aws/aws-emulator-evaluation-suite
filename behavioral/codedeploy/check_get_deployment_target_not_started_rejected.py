"""get-deployment-target-not-started-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deployment-target-not-started-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Right after CreateDeployment, GetDeploymentTarget raises
    DeploymentTargetDoesNotExistException for a never-member id and a real member; once targets
    resolve the member returns its record while the never-member stays rejected."""
    role_arn = _create_service_role(ctx)
    revision = _create_revision_bucket(ctx)
    app_name = _create_application(ctx)
    instance_name = _register_onprem_instance(ctx)
    group_name = _create_deployment_group(ctx, app_name, role_arn, instance_name)
    deployment_id = _create_deployment(ctx, app_name, group_name, revision)

    cd = ctx.client("codedeploy")
    fake_target_id = "i-0123456789abcdef0"
    assert fake_target_id != instance_name, (
        f"fake target id collided with the real registered instance name {instance_name!r}"
    )

    # Both refusals name the target by ARN. The on-premises instance's ARN carries a
    # server-minted suffix, so it is read back from GetOnPremisesInstance; the fake id is
    # rendered as an EC2 instance ARN in the same partition, region and account.
    instance_arn = cd.get_on_premises_instance(instanceName=instance_name)["instanceInfo"][
        "instanceArn"
    ]
    _arn, partition, _svc, region, account = instance_arn.split(":")[:5]
    fake_target_arn = f"arn:{partition}:ec2:{region}:{account}:instance/{fake_target_id}"

    # AWS resolves group membership faster than a client round trip, so the early reads see
    # DeploymentTargetDoesNotExistException rather than DeploymentNotStartedException.
    code_fake_early, message_fake_early = _error(
        lambda: cd.get_deployment_target(deploymentId=deployment_id, targetId=fake_target_id)
    )
    assert code_fake_early == "DeploymentTargetDoesNotExistException", (
        f"expected a target id that will never belong to this deployment to be rejected "
        f"as not-a-member from the very first read, got {code_fake_early!r}"
    )
    assert message_fake_early == (
        f"The target {fake_target_arn} is not part of deployment {deployment_id}"
    ), message_fake_early

    code_real_early, message_real_early = _error(
        lambda: cd.get_deployment_target(deploymentId=deployment_id, targetId=instance_name)
    )
    assert code_real_early == "DeploymentTargetDoesNotExistException", (
        f"expected DeploymentTargetDoesNotExistException for the real registered instance "
        f"before its per-target record has been created, got {code_real_early!r}"
    )
    assert message_real_early == (
        f"The target {instance_arn} is not part of deployment {deployment_id}"
    ), message_real_early

    # Poll ListDeploymentTargets (an independent read, at a different operation than the
    # one under test) until the deployment has resolved its real target -- proof that
    # target resolution has actually happened, not a bare sleep.
    def _list_targets():
        try:
            return cd.list_deployment_targets(deploymentId=deployment_id)["targetIds"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DeploymentNotStartedException":
                return []
            raise

    target_ids = _poll_until(
        _list_targets, lambda ids: len(ids) > 0, timeout_s=120.0, interval_s=3.0
    )
    assert instance_name in target_ids, (
        f"expected the registered on-premises instance {instance_name!r} among resolved "
        f"targets, got {target_ids!r}"
    )

    real_target = cd.get_deployment_target(
        deploymentId=deployment_id, targetId=instance_name
    )["deploymentTarget"]
    assert real_target["instanceTarget"]["targetId"] == instance_name, (
        f"expected the real target's own record to name itself, got {real_target!r}"
    )

    code_fake_late, message_fake_late = _error(
        lambda: cd.get_deployment_target(deploymentId=deployment_id, targetId=fake_target_id)
    )
    assert code_fake_late == "DeploymentTargetDoesNotExistException", (
        f"expected the never-a-member target id to still be rejected as not-a-member once "
        f"the deployment had resolved its real targets, got {code_fake_late!r}"
    )
    assert message_fake_late == (
        f"The target {fake_target_arn} is not part of deployment {deployment_id}"
    ), message_fake_late


def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-role-")
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_revision_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cd-rev-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    key = "sim2real-app.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "appspec.yml",
            "version: 0.0\nos: linux\nfiles:\n  - source: /\n    destination: /tmp/sim2real\n",
        )
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
    return {"bucket": bucket, "key": key}


def _create_application(ctx):
    cd = ctx.client("codedeploy")
    app_name = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))
    return app_name


def _register_onprem_instance(ctx):
    iam = ctx.client("iam")
    cd = ctx.client("codedeploy")
    user_name = ctx.unique_name("sim2real-cd-onprem-user-")
    user_arn = iam.create_user(
        UserName=user_name, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    instance_name = ctx.unique_name("sim2real-cd-onprem-")
    cd.register_on_premises_instance(instanceName=instance_name, iamUserArn=user_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=instance_name))
    cd.add_tags_to_on_premises_instances(
        tags=[{"Key": "sim2real-tag", "Value": instance_name}], instanceNames=[instance_name]
    )
    return instance_name


def _create_deployment_group(ctx, app_name, role_arn, instance_name):
    cd = ctx.client("codedeploy")
    group_name = ctx.unique_name("sim2real-cd-dg-")
    deadline = time.monotonic() + 30.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            cd.create_deployment_group(
                applicationName=app_name,
                deploymentGroupName=group_name,
                serviceRoleArn=role_arn,
                onPremisesInstanceTagFilters=[
                    {"Key": "sim2real-tag", "Value": instance_name, "Type": "KEY_AND_VALUE"}
                ],
                tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleException":
                raise
            last_error = exc
            time.sleep(2.0)
    else:
        raise AssertionError(f"service role never became assumable: {last_error}")
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(
            applicationName=app_name, deploymentGroupName=group_name
        )
    )
    return group_name


def _create_deployment(ctx, app_name, group_name, revision):
    cd = ctx.client("codedeploy")
    resp = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=group_name,
        revision={
            "revisionType": "S3",
            "s3Location": {
                "bucket": revision["bucket"],
                "key": revision["key"],
                "bundleType": "zip",
            },
        },
    )
    return resp["deploymentId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
