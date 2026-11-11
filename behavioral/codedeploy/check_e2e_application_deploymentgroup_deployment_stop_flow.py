"""e2e-application-deploymentgroup-deployment-stop-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-application-deploymentgroup-deployment-stop-flow"
GROUP = "e2e"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deployment to a registered on-premises instance lists it as an InstanceTarget, StopDeployment
    ends it Stopped, and the deleted group and application then read as not found."""
    codedeploy = ctx.client("codedeploy")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # A registered on-premises instance is a real, queryable deployment target that
    # doesn't require provisioning live EC2/agent infrastructure: CodeDeploy's target
    # discovery is a pure control-plane match against tag filters.
    instance_name = ctx.unique_name("sim2real-onprem-")
    iam_user_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-user-')}"
    codedeploy.register_on_premises_instance(instanceName=instance_name, iamUserArn=iam_user_arn)
    ctx.on_cleanup(lambda: codedeploy.deregister_on_premises_instance(instanceName=instance_name))

    tag_key, tag_value = "sim2real-stopflow-key", ctx.unique_name("sim2real-stopflow-val-")
    codedeploy.add_tags_to_on_premises_instances(tags=[{"Key": tag_key, "Value": tag_value}], instanceNames=[instance_name])

    app_name = ctx.unique_name("sim2real-cdapp-")
    codedeploy.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: _delete_application_if_present(codedeploy, app_name))

    role_arn = _create_codedeploy_service_role(ctx)

    dg_name = ctx.unique_name("sim2real-cddg-")
    _create_deployment_group_with_retry(
        codedeploy,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
        onPremisesInstanceTagFilters=[{"Key": tag_key, "Value": tag_value, "Type": "KEY_AND_VALUE"}],
    )
    ctx.on_cleanup(lambda: _delete_deployment_group_if_present(codedeploy, app_name, dg_name))

    revision = _upload_revision_bundle(ctx)
    deployment_id = codedeploy.create_deployment(
        applicationName=app_name, deploymentGroupName=dg_name, revision=revision
    )["deploymentId"]

    # Observe the on-premises instance surfacing as a real target of this deployment.
    def _target_visible():
        try:
            names = codedeploy.list_deployment_instances(deploymentId=deployment_id)["instancesList"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "DeploymentNotStartedException":
                return False
            raise
        return instance_name in names

    assert _poll_until(_target_visible, timeout_s=90, interval_s=3), (
        "the registered on-premises instance never appeared as a deployment target"
    )

    target = codedeploy.get_deployment_target(deploymentId=deployment_id, targetId=instance_name)["deploymentTarget"]
    assert target["deploymentTargetType"] == "InstanceTarget", (
        f"expected deploymentTargetType InstanceTarget, got {target['deploymentTargetType']}"
    )
    assert target["instanceTarget"]["targetId"] == instance_name, (
        f"expected target id {instance_name!r}, got {target['instanceTarget']['targetId']!r}"
    )

    codedeploy.stop_deployment(deploymentId=deployment_id)

    def _stopped():
        return codedeploy.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["status"] == "Stopped"

    assert _poll_until(_stopped, timeout_s=90, interval_s=3), "deployment never reached terminal Stopped status"

    final = codedeploy.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
    assert final["status"] == "Stopped", f"expected status Stopped, got {final['status']}"

    # Delete the deployment group and application here and read both back as not found.
    codedeploy.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)
    dg_gone = _error(
        lambda: codedeploy.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)
    )
    expected = ("DeploymentGroupDoesNotExistException", f"No Deployment Group found for name: {dg_name}")
    assert dg_gone == expected, f"expected {expected!r} after delete, got {dg_gone!r}"

    codedeploy.delete_application(applicationName=app_name)
    app_gone = _error(lambda: codedeploy.get_application(applicationName=app_name))
    expected = ("ApplicationDoesNotExistException", f"No application found for name: {app_name}")
    assert app_gone == expected, f"expected {expected!r} after delete, got {app_gone!r}"


def _poll_until(probe, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        if probe():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn() raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_application_if_present(codedeploy, app_name) -> None:
    try:
        codedeploy.delete_application(applicationName=app_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ApplicationDoesNotExistException":
            raise


def _delete_deployment_group_if_present(codedeploy, app_name, dg_name) -> None:
    try:
        codedeploy.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in (
            "ApplicationDoesNotExistException",
            "DeploymentGroupDoesNotExistException",
        ):
            raise


def _create_codedeploy_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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


def _create_deployment_group_with_retry(codedeploy, *, timeout_s=45.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return codedeploy.create_deployment_group(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _upload_revision_bundle(ctx) -> dict:
    import io
    import zipfile

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cdrev-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

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
