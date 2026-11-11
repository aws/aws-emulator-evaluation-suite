"""deployment-create-stop-status-transition."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-create-stop-status-transition"
GROUP = "state-machine"
SERVICES = ["codedeploy"]

_TERMINAL_STATUSES = {"Succeeded", "Failed", "Stopped"}


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeployment followed immediately by StopDeployment transitions the deployment
    to the terminal 'Stopped' status, as observed via GetDeployment."""
    codedeploy = ctx.client("codedeploy")

    role_arn = _create_codedeploy_service_role(ctx)
    bucket = _create_revision_bucket(ctx)
    key = "revisions/app.zip"
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=_build_minimal_appspec_zip())

    app_name = ctx.unique_name("sim2real-cd-app-")
    codedeploy.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: codedeploy.delete_application(applicationName=app_name))

    # Register a real (but agent-less) on-premises instance and tag it so the deployment
    # group targets exactly one instance. Because no CodeDeploy agent will ever poll in,
    # the deployment sits in a non-terminal state (Created/Queued/InProgress) instead of
    # failing instantly with NO_INSTANCES -- giving StopDeployment a real window to apply.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    instance_name = ctx.unique_name("sim2real-cd-stopdep-onprem-")
    user_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-stopdep-user-')}"
    codedeploy.register_on_premises_instance(instanceName=instance_name, iamUserArn=user_arn)
    ctx.on_cleanup(lambda: _safe_deregister(codedeploy, instance_name))
    tag_key = "sim2real-cd-stopdep-tag"
    codedeploy.add_tags_to_on_premises_instances(
        tags=[{"Key": tag_key, "Value": instance_name}], instanceNames=[instance_name]
    )

    group_name = ctx.unique_name("sim2real-cd-dg-")
    _create_deployment_group_with_role_retry(
        ctx,
        codedeploy,
        app_name,
        group_name,
        role_arn,
        onPremisesInstanceTagFilters=[
            {"Key": tag_key, "Value": instance_name, "Type": "KEY_AND_VALUE"}
        ],
    )
    ctx.on_cleanup(
        lambda: codedeploy.delete_deployment_group(
            applicationName=app_name, deploymentGroupName=group_name
        )
    )

    revision = {
        "revisionType": "S3",
        "s3Location": {"bucket": bucket, "key": key, "bundleType": "zip"},
    }

    final_status = None
    last_error = None
    # A deployment against zero matching instances can reach a terminal state quickly;
    # retry the create+stop race a few times so a single lost race doesn't fail the check.
    for _attempt in range(3):
        deployment_id = codedeploy.create_deployment(
            applicationName=app_name,
            deploymentGroupName=group_name,
            revision=revision,
        )["deploymentId"]
        try:
            stop_resp = codedeploy.stop_deployment(deploymentId=deployment_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DeploymentAlreadyCompletedException":
                last_error = e
                continue
            raise
        assert stop_resp["status"] in ("Pending", "Succeeded"), (
            f"unexpected StopDeployment status: {stop_resp['status']!r}"
        )
        final_status = _poll_deployment_status(codedeploy, deployment_id)
        break

    assert final_status is not None, (
        f"the deployment always reached a terminal state before StopDeployment could "
        f"apply, last error: {last_error}"
    )
    assert final_status == "Stopped", f"expected status Stopped, got {final_status}"


def _poll_deployment_status(codedeploy, deployment_id, timeout_s=420.0, interval_s=10.0):
    # The stop is asynchronous: CodeDeploy must "schedule" the stop command against the
    # deployment's target(s) before the overall deployment status flips to Stopped. With an
    # on-premises target whose agent never checks in, this can take several minutes -- so
    # this poll is intentionally generous, and re-issues StopDeployment periodically in case
    # the original request was superseded by an internal state refresh.
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = codedeploy.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["status"]
        if status in _TERMINAL_STATUSES:
            return status
        try:
            codedeploy.stop_deployment(deploymentId=deployment_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "DeploymentAlreadyCompletedException":
                raise
        time.sleep(interval_s)
    raise AssertionError(
        f"deployment {deployment_id} never reached a terminal status within {timeout_s}s "
        f"(last status={status!r})"
    )


# ===== helpers =====


def _create_codedeploy_service_role(ctx):
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_deployment_group_with_role_retry(
    ctx, codedeploy, application_name, deployment_group_name, role_arn, **kwargs
):
    # IAM role creation is eventually consistent; CodeDeploy may not be able to assume
    # a just-created role for tens of seconds.
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return codedeploy.create_deployment_group(
                applicationName=application_name,
                deploymentGroupName=deployment_group_name,
                serviceRoleArn=role_arn,
                **kwargs,
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException":
                last_err = e
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"deployment group never became creatable, last error: {last_err}")


def _create_revision_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cd-rev-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _safe_deregister(codedeploy, instance_name):
    try:
        codedeploy.deregister_on_premises_instance(instanceName=instance_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InstanceNotRegisteredException":
            raise


def _build_minimal_appspec_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "appspec.yml",
            "version: 0.0\nos: linux\nfiles:\n  - source: /\n    destination: /tmp\n",
        )
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
