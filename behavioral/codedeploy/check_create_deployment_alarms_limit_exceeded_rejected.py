"""create-deployment-alarms-limit-exceeded-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-alarms-limit-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment overriding the alarm configuration with more than the 50-alarm limit
    the error message names raises AlarmsLimitExceededException and creates no deployment
    record; 10 alarms is accepted and the deployment proceeds."""
    role_arn = _create_codedeploy_service_role(ctx)
    bundle = _upload_minimal_bundle(ctx)
    app_name, group_name = _create_app_and_empty_deployment_group(ctx, role_arn)
    cd = ctx.client("codedeploy")

    too_many_alarms = {
        "alarms": [{"name": f"sim2real-alarm-{i}"} for i in range(51)],
        "enabled": True,
        "ignorePollAlarmFailure": True,
    }
    code, message = _error(
        lambda: cd.create_deployment(
            applicationName=app_name,
            deploymentGroupName=group_name,
            revision={"revisionType": "S3", "s3Location": bundle},
            overrideAlarmConfiguration=too_many_alarms,
        )
    )
    assert code == "AlarmsLimitExceededException", f"expected AlarmsLimitExceededException, got {code!r}"
    assert message == "Deployments cannot contain more than 50 alarms.", message

    # effect absent: no deployment record was created as a result of the rejected call
    deployments = cd.list_deployments(applicationName=app_name, deploymentGroupName=group_name)[
        "deployments"
    ]
    assert deployments == [], f"expected no deployment record after the rejected call, got {deployments!r}"

    # positive control: an alarm list within the limit (10) is accepted
    ok_alarms = {
        "alarms": [{"name": f"sim2real-alarm-{i}"} for i in range(10)],
        "enabled": True,
        "ignorePollAlarmFailure": True,
    }
    deployment_id = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=group_name,
        revision={"revisionType": "S3", "s3Location": bundle},
        overrideAlarmConfiguration=ok_alarms,
    )["deploymentId"]
    status = _wait_terminal(ctx, deployment_id)
    assert status == "Failed", (
        f"expected the accepted deployment (deployment group matches no instances) to end "
        f"Failed, got {status!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _upload_minimal_bundle(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cd-bundle-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("appspec.yml", "version: 0.0\nos: linux\nfiles: []\n")
    key = "bundle.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    return {"bucket": bucket, "key": key, "bundleType": "zip"}


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_app_and_empty_deployment_group(ctx, role_arn):
    cd = ctx.client("codedeploy")
    app_name = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    group_name = ctx.unique_name("sim2real-cd-dg-")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cd.create_deployment_group(
                applicationName=app_name,
                deploymentGroupName=group_name,
                serviceRoleArn=role_arn,
                ec2TagFilters=[
                    {
                        "Key": "sim2real-behavioral-nonexistent-tag",
                        "Value": "none",
                        "Type": "KEY_AND_VALUE",
                    }
                ],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidRoleException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app_name, deploymentGroupName=group_name)
    )
    return app_name, group_name


def _wait_terminal(ctx, deployment_id, timeout_s=240.0):
    cd = ctx.client("codedeploy")
    terminal = {"Succeeded", "Failed", "Stopped"}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["status"]
        if status in terminal:
            return status
        time.sleep(5.0)
    raise AssertionError(f"deployment {deployment_id} never reached a terminal state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
