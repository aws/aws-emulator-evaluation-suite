"""e2e-onprem-deployment-full-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-onprem-deployment-full-flow"
GROUP = "e2e"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A tag-filtered on-premises deployment targets the registered instance, stops (or is already
    completed) without Succeeded, and deregister/delete make the instance and app unreadable."""
    cd = ctx.client("codedeploy")
    role_arn = _create_service_role(ctx)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    instance_name = ctx.unique_name("sim2real-cd-onprem-")
    cd.register_on_premises_instance(
        instanceName=instance_name, iamUserArn=f"arn:aws:iam::{account_id}:user/{instance_name}"
    )
    ctx.on_cleanup(lambda: _deregister_if_present(cd, instance_name))
    instance_arn = _wait_instance_registered(cd, instance_name)["instanceArn"]

    tag_key = ctx.unique_name("sim2real-tag-")
    cd.add_tags_to_on_premises_instances(tags=[{"Key": tag_key, "Value": "match"}], instanceNames=[instance_name])

    app = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(applicationName=app, computePlatform="Server")
    ctx.on_cleanup(lambda: _delete_application_if_present(cd, app))

    group = ctx.unique_name("sim2real-cd-dg-")
    _create_deployment_group(
        ctx, cd, app, group, role_arn,
        onPremisesInstanceTagFilters=[{"Key": tag_key, "Value": "match", "Type": "KEY_AND_VALUE"}],
    )

    revision = _upload_s3_revision(ctx)
    deployment_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=group, revision=revision["location"]
    )["deploymentId"]

    # Poll for targets, not a transient status: an agentless instance fails its health check fast.
    target_ids = _wait_for_targets(cd, deployment_id)
    assert len(target_ids) == 1, target_ids
    target = cd.get_deployment_target(deploymentId=deployment_id, targetId=target_ids[0])["deploymentTarget"]
    assert target["deploymentTargetType"] == "InstanceTarget", target["deploymentTargetType"]
    assert target["instanceTarget"]["targetArn"] == instance_arn, target["instanceTarget"]["targetArn"]

    instances_list = cd.list_deployment_instances(deploymentId=deployment_id)["instancesList"]
    assert instance_name in instances_list, instances_list

    # The agentless deployment may already be terminal, so StopDeployment can be rejected as
    # completed; it must never end Succeeded since no agent serviced it.
    try:
        stop_resp = cd.stop_deployment(deploymentId=deployment_id)
        assert stop_resp["status"] in ("Succeeded", "Pending"), stop_resp["status"]
        stopped = _wait_deployment_status(cd, deployment_id, {"Succeeded", "Failed", "Stopped"})
        assert stopped["status"] in ("Stopped", "Failed"), stopped["status"]
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "DeploymentAlreadyCompletedException", exc.response["Error"]
        final = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
        assert final["status"] in ("Failed", "Stopped"), final["status"]
        state = {"Stopped": "ABORTED"}.get(final["status"], final["status"].upper())
        completed = f"The deployment {deployment_id} is already in state {state}"
        assert exc.response["Error"].get("Message") == completed, (completed, exc.response["Error"])

    # CodeDeploy keeps no readable "deregistered" record; the instance disappears outright.
    cd.deregister_on_premises_instance(instanceName=instance_name)
    deregistered = _error(lambda: cd.get_on_premises_instance(instanceName=instance_name))
    assert deregistered == (
        "InstanceNotRegisteredException", f"The requested host does not exist. Host: {instance_name}"
    ), deregistered

    # Deleting the application cascades to its deployment group.
    cd.delete_application(applicationName=app)
    app_gone = _error(lambda: cd.get_application(applicationName=app))
    assert app_gone == ("ApplicationDoesNotExistException", f"No application found for name: {app}"), app_gone


def _wait_instance_registered(cd, instance_name, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cd.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InstanceNotRegisteredException" or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _wait_for_targets(cd, deployment_id, timeout_s=120.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last_ids = []
    while time.monotonic() < deadline:
        try:
            last_ids = cd.list_deployment_targets(deploymentId=deployment_id)["targetIds"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DeploymentNotStartedException":
                raise
            last_ids = []
        if last_ids:
            return last_ids
        time.sleep(interval_s)
    raise AssertionError(f"deployment {deployment_id} never surfaced any deployment targets within {timeout_s}s")

def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn() raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _deregister_if_present(cd, instance_name):
    try:
        cd.deregister_on_premises_instance(instanceName=instance_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InstanceNotRegisteredException":
            raise


def _delete_application_if_present(cd, application_name):
    try:
        cd.delete_application(applicationName=application_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ApplicationDoesNotExistException":
            raise


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
    ctx.on_cleanup(lambda: _delete_deployment_group_if_present(cd, application_name, deployment_group_name))
    return resp


def _delete_deployment_group_if_present(cd, application_name, deployment_group_name):
    try:
        cd.delete_deployment_group(applicationName=application_name, deploymentGroupName=deployment_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ApplicationDoesNotExistException", "DeploymentGroupDoesNotExistException"):
            raise


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


def _wait_deployment_status(cd, deployment_id, target_statuses, timeout_s=150.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
        if last["status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"deployment {deployment_id} did not reach {target_statuses} within {timeout_s}s "
        f"(last status={last['status'] if last else None})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
