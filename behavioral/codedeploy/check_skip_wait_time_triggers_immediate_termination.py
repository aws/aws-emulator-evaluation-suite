"""skip-wait-time-triggers-immediate-termination."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "skip-wait-time-triggers-immediate-termination"
GROUP = "server-side"
SERVICES = ["codedeploy"]

_SRC_V1 = "def handler(event, context):\n    return {'version': 1}\n"
_SRC_V2 = "def handler(event, context):\n    return {'version': 2}\n"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SkipWaitTimeForInstanceTermination on a terminal deployment is rejected with
    DeploymentAlreadyCompletedException without mutating its status/errorInformation, while a
    fresh in-progress deployment on the same group is not rejected that way and stops cleanly."""
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")
    role_arn = _create_lambda_codedeploy_role(ctx)

    app_name = ctx.unique_name("sim2real-cd-skipwait-app-")
    cd.create_application(applicationName=app_name, computePlatform="Lambda")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    group_name = ctx.unique_name("sim2real-cd-skipwait-group-")
    _create_deployment_group_with_retry(ctx, cd, app_name, group_name, role_arn)

    # The referenced Lambda function does not exist, so the deployment fails
    # deterministically, reaching a terminal state without EC2/agent infrastructure.
    missing_fn_revision = _lambda_appspec_revision(
        "sim2real-cd-skipwait-missing-fn", "live", "1", "2"
    )

    deploy_a_id = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=group_name,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        revision=missing_fn_revision,
    )["deploymentId"]
    info_before = _poll_deployment_terminal(cd, deploy_a_id)
    assert info_before["status"] in ("Failed", "Succeeded", "Stopped"), (
        f"expected a terminal status for {deploy_a_id}, got {info_before['status']}"
    )

    refusal = _error(
        lambda: cd.skip_wait_time_for_instance_termination(deploymentId=deploy_a_id)
    )
    # The refusal names the internal state: a Stopped deployment is ABORTED.
    state = {"Stopped": "ABORTED"}.get(info_before["status"], info_before["status"].upper())
    expected = ("DeploymentAlreadyCompletedException",
                f"The deployment {deploy_a_id} has already completed, current state {state}.")
    assert refusal == expected, (
        f"expected {expected!r} for a terminal deployment, got {refusal!r}"
    )

    info_after = cd.get_deployment(deploymentId=deploy_a_id)["deploymentInfo"]
    assert info_after["status"] == info_before["status"], (
        f"rejected SkipWaitTime call mutated status: {info_before['status']!r} -> "
        f"{info_after['status']!r}"
    )
    assert info_after.get("errorInformation") == info_before.get("errorInformation"), (
        f"rejected SkipWaitTime call mutated errorInformation: "
        f"{info_before.get('errorInformation')!r} -> {info_after.get('errorInformation')!r}"
    )

    # Positive control: a real Lambda function under a multi-minute canary config stays
    # in progress long enough for SkipWaitTime and StopDeployment to act on it.
    exec_role_arn = _create_exec_role(ctx)
    fn_name = ctx.unique_name("sim2real-cd-skipwait-fn-")
    _create_function_with_retry(ctx, lam, fn_name, exec_role_arn, _lambda_zip(_SRC_V1))
    _wait_active(lam, fn_name)
    v1 = lam.publish_version(FunctionName=fn_name)["Version"]
    lam.update_function_code(FunctionName=fn_name, ZipFile=_lambda_zip(_SRC_V2))
    _wait_updated(lam, fn_name)
    v2 = lam.publish_version(FunctionName=fn_name)["Version"]
    lam.create_alias(FunctionName=fn_name, Name="live", FunctionVersion=v1)

    real_revision = _lambda_appspec_revision(fn_name, "live", v1, v2)
    deploy_b_id = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=group_name,
        deploymentConfigName="CodeDeployDefault.LambdaCanary10Percent5Minutes",
        revision=real_revision,
    )["deploymentId"]

    # Pins deploy_a's rejection to completion state rather than to the Lambda
    # platform lacking an instance-termination step.
    early_code, _ = _error(
        lambda: cd.skip_wait_time_for_instance_termination(deploymentId=deploy_b_id)
    )
    assert early_code != "DeploymentAlreadyCompletedException", (
        f"deploy_b ({deploy_b_id}) is still in progress, so SkipWaitTime must not be "
        f"rejected with the same code as an already-completed deployment; got {early_code}"
    )

    stop_resp = _stop_deployment_with_retry(cd, deploy_b_id)
    assert stop_resp["status"] in ("Pending", "Succeeded"), f"unexpected stop_resp {stop_resp}"
    final_b = _poll_deployment_terminal(cd, deploy_b_id)
    assert final_b["status"] == "Stopped", (
        f"expected Stopped, got {final_b['status']} "
        f"(errorInformation={final_b.get('errorInformation')})"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected success raises rather than
    being reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _lambda_appspec_revision(
    function_name: str, alias: str, current_version: str, target_version: str
) -> dict:
    appspec = json.dumps(
        {
            "version": "0.0",
            "resources": [
                {
                    "myLambdaFunction": {
                        "type": "AWS::Lambda::Function",
                        "properties": {
                            "name": function_name,
                            "alias": alias,
                            "currentversion": current_version,
                            "targetversion": target_version,
                        },
                    }
                }
            ],
        }
    )
    return {"revisionType": "AppSpecContent", "appSpecContent": {"content": appspec}}


def _lambda_zip(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-skipwait-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-cd-skipwait"},
        ],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    return role_arn


def _create_function_with_retry(
    ctx, lam, name: str, role_arn: str, code_bytes: bytes, timeout_s: float = 120.0
) -> None:
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": code_bytes},
        Timeout=15,
        Publish=False,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cd-skipwait"},
    )
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            ctx.on_cleanup(lambda n=name: lam.delete_function(FunctionName=n))
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            last_exc = exc
            if code == "InvalidParameterValueException" and "role" in message.lower():
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"lambda function {name} never became creatable: {last_exc}")


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active (last state {state})")


def _wait_updated(lam, name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = lam.get_function(FunctionName=name)["Configuration"]["LastUpdateStatus"]
        if status == "Successful":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} update never completed (last status {status})")


def _create_lambda_codedeploy_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-skipwait-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codedeploy.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-cd-skipwait"},
        ],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRoleForLambda"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_deployment_group_with_retry(
    ctx, cd, app_name: str, group_name: str, role_arn: str, timeout_s: float = 90.0
) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            cd.create_deployment_group(
                applicationName=app_name,
                deploymentGroupName=group_name,
                serviceRoleArn=role_arn,
                deploymentStyle={
                    "deploymentType": "BLUE_GREEN",
                    "deploymentOption": "WITH_TRAFFIC_CONTROL",
                },
            )
            ctx.on_cleanup(
                lambda: cd.delete_deployment_group(
                    applicationName=app_name, deploymentGroupName=group_name
                )
            )
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "InvalidRoleException":
                raise
            time.sleep(3)
    raise AssertionError(f"deployment group never became creatable, last error {last_code}")


def _stop_deployment_with_retry(cd, deployment_id: str, timeout_s: float = 60.0):
    """StopDeployment can transiently 400 with DeploymentAlreadyCompletedException
    if called in the brief window before the deployment engine has registered the
    deployment as in-progress; retry until it is genuinely stoppable or completed."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return cd.stop_deployment(deploymentId=deployment_id)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "InvalidDeploymentStatusException":
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"deployment {deployment_id} never became stoppable: {last_exc}")


def _poll_deployment_terminal(cd, deployment_id: str, timeout_s: float = 300.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    terminal = {"Succeeded", "Failed", "Stopped"}
    info = None
    while time.monotonic() < deadline:
        info = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
        if info["status"] in terminal:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"deployment {deployment_id} did not reach a terminal state (last={info})")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

