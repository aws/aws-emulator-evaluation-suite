"""lifecycle-event-hook-status-gates-deployment-progress."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lifecycle-event-hook-status-gates-deployment-progress"
GROUP = "server-side"
SERVICES = ["codedeploy"]

_APP_SRC_V1 = "def handler(event, context):\n    return {'version': 1}\n"
_APP_SRC_V2 = "def handler(event, context):\n    return {'version': 2}\n"
_HOOK_SRC = (
    "import os\n"
    "import boto3\n\n"
    "def handler(event, context):\n"
    "    client = boto3.client('codedeploy')\n"
    "    client.put_lifecycle_event_hook_execution_status(\n"
    "        deploymentId=event['DeploymentId'],\n"
    "        lifecycleEventHookExecutionId=event['LifecycleEventHookExecutionId'],\n"
    "        status=os.environ.get('HOOK_STATUS', 'Succeeded'),\n"
    "    )\n"
    "    return {'reported': True}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda deployment whose BeforeAllowTraffic hook reports Failed ends Failed with the alias still
    on v1, while the twin that reports Succeeded ends Succeeded with the alias on v2."""
    lam = ctx.client("lambda")
    cd = ctx.client("codedeploy")

    exec_role_arn = _create_exec_role(ctx)
    service_role_arn = _create_codedeploy_service_role(ctx)

    app_function_name = ctx.unique_name("sim2real-cd-lhk-app-")
    _create_function_with_retry(
        ctx, lam, app_function_name, exec_role_arn, _lambda_zip(_APP_SRC_V1)
    )
    _wait_active(lam, app_function_name)
    v1 = lam.publish_version(FunctionName=app_function_name)["Version"]

    lam.update_function_code(FunctionName=app_function_name, ZipFile=_lambda_zip(_APP_SRC_V2))
    _wait_updated(lam, app_function_name)
    v2 = lam.publish_version(FunctionName=app_function_name)["Version"]

    lam.create_alias(FunctionName=app_function_name, Name="live", FunctionVersion=v1)

    # NOTE: CodeDeploy's own managed policy (AWSCodeDeployRoleForLambda) only grants
    # lambda:InvokeFunction on arn:...:function:CodeDeployHook_* -- the hook function
    # name MUST carry that prefix or the automatic hook invocation itself is denied.
    hook_ok_name = "CodeDeployHook_" + ctx.unique_name("sim2real-cd-lhk-ok-")
    _create_function_with_retry(
        ctx, lam, hook_ok_name, exec_role_arn, _lambda_zip(_HOOK_SRC), env={"HOOK_STATUS": "Succeeded"}
    )
    _wait_active(lam, hook_ok_name)

    hook_fail_name = "CodeDeployHook_" + ctx.unique_name("sim2real-cd-lhk-fail-")
    _create_function_with_retry(
        ctx, lam, hook_fail_name, exec_role_arn, _lambda_zip(_HOOK_SRC), env={"HOOK_STATUS": "Failed"}
    )
    _wait_active(lam, hook_fail_name)

    cd_app_name = ctx.unique_name("sim2real-cd-lhk-cdapp-")
    cd.create_application(
        applicationName=cd_app_name,
        computePlatform="Lambda",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=cd_app_name))

    group_name = ctx.unique_name("sim2real-cd-lhk-group-")
    _create_deployment_group_with_retry(ctx, cd, cd_app_name, group_name, service_role_arn)

    # --- a Failed hook report must halt the deployment before traffic shifts ---
    fail_revision = _lambda_hook_appspec(app_function_name, "live", v1, v2, hook_fail_name)
    fail_deploy_id = cd.create_deployment(
        applicationName=cd_app_name,
        deploymentGroupName=group_name,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        revision=fail_revision,
    )["deploymentId"]
    fail_info = _poll_deployment_terminal(cd, fail_deploy_id)
    fail_hook_status = _before_allow_traffic_status(cd, fail_deploy_id)
    fail_alias = lam.get_alias(FunctionName=app_function_name, Name="live")
    assert fail_info["status"] == "Failed", (
        f"deployment {fail_deploy_id!r} whose BeforeAllowTraffic hook reported 'Failed' "
        f"ended {fail_info['status']!r}, expected 'Failed'"
    )
    assert fail_hook_status == "Failed", (
        f"the BeforeAllowTraffic lifecycle event on deployment {fail_deploy_id!r} reads "
        f"{fail_hook_status!r}, expected 'Failed'"
    )
    assert fail_alias["FunctionVersion"] == v1, (
        f"the 'live' alias moved to {fail_alias['FunctionVersion']!r} after a deployment "
        f"whose BeforeAllowTraffic hook reported 'Failed'; expected it to stay at {v1!r}"
    )

    # --- an identical deployment with a Succeeded hook report completes ---
    ok_revision = _lambda_hook_appspec(app_function_name, "live", v1, v2, hook_ok_name)
    ok_deploy_id = cd.create_deployment(
        applicationName=cd_app_name,
        deploymentGroupName=group_name,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        revision=ok_revision,
    )["deploymentId"]
    ok_info = _poll_deployment_terminal(cd, ok_deploy_id)
    ok_hook_status = _before_allow_traffic_status(cd, ok_deploy_id)
    ok_alias = lam.get_alias(FunctionName=app_function_name, Name="live")
    assert ok_info["status"] == "Succeeded", (
        f"deployment {ok_deploy_id!r} whose BeforeAllowTraffic hook reported 'Succeeded' "
        f"ended {ok_info['status']!r}, expected 'Succeeded'"
    )
    assert ok_hook_status == "Succeeded", (
        f"the BeforeAllowTraffic lifecycle event on deployment {ok_deploy_id!r} reads "
        f"{ok_hook_status!r}, expected 'Succeeded'"
    )
    assert ok_alias["FunctionVersion"] == v2, (
        f"the 'live' alias reads {ok_alias['FunctionVersion']!r} after a deployment whose "
        f"BeforeAllowTraffic hook reported 'Succeeded'; expected it to move to {v2!r}"
    )


def _lambda_zip(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-lhk-exec-")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))

    inline_name = "codedeploy-callback"
    callback_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "codedeploy:PutLifecycleEventHookExecutionStatus",
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=inline_name, PolicyDocument=json.dumps(callback_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_name))
    return role_arn


def _create_codedeploy_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-lhk-svc-")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRoleForLambda"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_function_with_retry(
    ctx, lam, name: str, role_arn: str, code_bytes: bytes, env: dict | None = None, timeout_s: float = 120.0
) -> None:
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": code_bytes},
        Timeout=15,
        Publish=False,
        Tags={"sim2real:managed": "true"},
    )
    if env is not None:
        kwargs["Environment"] = {"Variables": env}
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


def _lambda_hook_appspec(
    function_name: str, alias: str, current_version: str, target_version: str, hook_function_name: str
) -> dict:
    content = json.dumps(
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
            "hooks": [{"BeforeAllowTraffic": hook_function_name}],
        }
    )
    return {"revisionType": "AppSpecContent", "appSpecContent": {"content": content}}


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
                tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _before_allow_traffic_status(cd, deployment_id: str) -> str | None:
    target_ids = cd.list_deployment_targets(deploymentId=deployment_id)["targetIds"]
    for target_id in target_ids:
        target = cd.get_deployment_target(deploymentId=deployment_id, targetId=target_id)[
            "deploymentTarget"
        ]
        lambda_target = target.get("lambdaTarget") or {}
        for event in lambda_target.get("lifecycleEvents", []):
            if event.get("lifecycleEventName") == "BeforeAllowTraffic":
                return event.get("status")
    return None


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
