"""concurrent-deployment-same-group-rejected-while-active."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-deployment-same-group-rejected-while-active"
GROUP = "concurrency"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """While a deployment is InProgress a second CreateDeployment to the same group is refused with
    DeploymentLimitExceededException; once the first Succeeded a new deployment runs to Succeeded."""
    lambda_client = ctx.client("lambda")
    cd = ctx.client("codedeploy")

    exec_role_arn = _create_lambda_execution_role(ctx)
    fn_name = ctx.unique_name("sim2real-cd-fn-")
    v1 = _create_function(ctx, lambda_client, fn_name, exec_role_arn, b"payload-v1")
    lambda_client.create_alias(FunctionName=fn_name, Name="live", FunctionVersion=v1)
    v2 = _publish_new_version(lambda_client, fn_name, b"payload-v2")
    v3 = _publish_new_version(lambda_client, fn_name, b"payload-v3")

    # A hook Lambda that sleeps for a while before reporting the lifecycle event
    # Succeeded gives us a wide, deterministic window during which the deployment is
    # observably InProgress -- no reliance on bare sleeps in the assertion itself.
    hook_name = ctx.unique_name("sim2real-cd-hook-")
    _create_function(ctx, lambda_client, fn_name=hook_name, role_arn=exec_role_arn, payload=_hook_zip(delay_s=20), is_zip=True)

    service_role_arn = _create_codedeploy_lambda_role(ctx, hook_arn=_fn_arn(lambda_client, hook_name))
    app = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(
        applicationName=app, computePlatform="Lambda",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cd"}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app))
    group = ctx.unique_name("sim2real-cd-dg-")
    group_id = _create_lambda_deployment_group(ctx, cd, app, group, service_role_arn)

    content1 = _appspec(fn_name, v1, v2, hook_function_name=hook_name)
    dep1_id = _create_deployment_with_retry(cd, app, group, {"revisionType": "AppSpecContent", "appSpecContent": {"content": content1}})
    ctx.on_cleanup(lambda: _stop_if_active(cd, dep1_id))

    dep1_state = _wait_deployment_status(cd, dep1_id, {"InProgress", "Succeeded", "Failed", "Stopped"}, timeout_s=60)
    assert dep1_state["status"] == "InProgress", f"expected dep1 {dep1_id!r} InProgress, got {dep1_state}"

    # While dep1 is still InProgress (sleeping in its hook), a second CreateDeployment
    # against the same group must be rejected outright -- not queued, not parallel.
    content2 = _appspec(fn_name, v2, v3)
    refusal = _error(lambda: cd.create_deployment(
        applicationName=app, deploymentGroupName=group,
        revision={"revisionType": "AppSpecContent", "appSpecContent": {"content": content2}},
    ))
    expected = (
        "DeploymentLimitExceededException",
        f"The Deployment Group '{group} (id={group_id})' already has an active Deployment '{dep1_id}'",
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # BatchGetDeployments while dep1 is the sole active deployment: confirms via a
    # second read path that only dep1 is non-terminal.
    batch = cd.batch_get_deployments(deploymentIds=[dep1_id])["deploymentsInfo"]
    assert len(batch) == 1 and batch[0]["deploymentId"] == dep1_id, (
        f"expected BatchGetDeployments([{dep1_id!r}]) to return exactly that one deployment, got {batch!r}"
    )
    assert batch[0]["status"] == "InProgress", f"expected dep1 {dep1_id!r} InProgress via BatchGetDeployments, got {batch[0]['status']!r}"

    dep1_final = _wait_deployment_status(cd, dep1_id, {"Succeeded", "Failed", "Stopped"}, timeout_s=120)
    assert dep1_final["status"] == "Succeeded", f"expected dep1 {dep1_id!r} to end Succeeded, got {dep1_final}"

    # Once dep1 is terminal, the group accepts a new deployment again -- serialization
    # is temporal (mutual exclusion while active), not a permanent lockout.
    dep2_id = _create_deployment_with_retry(cd, app, group, {"revisionType": "AppSpecContent", "appSpecContent": {"content": content2}})
    ctx.on_cleanup(lambda: _stop_if_active(cd, dep2_id))
    dep2_final = _wait_deployment_status(cd, dep2_id, {"Succeeded", "Failed", "Stopped"}, timeout_s=60)
    assert dep2_final["status"] == "Succeeded", f"expected the post-terminal dep2 {dep2_id!r} to end Succeeded, got {dep2_final}"


def _error(fn):
    """The raised ClientError's (code, message). Raises if the call unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        "the call was expected to be refused with DeploymentLimitExceededException but it SUCCEEDED"
    )


def _stop_if_active(cd, deployment_id):
    try:
        cd.stop_deployment(deploymentId=deployment_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DeploymentAlreadyCompletedException":
            raise


def _appspec(fn_name, current_version, target_version, hook_function_name=None):
    lines = [
        "version: 0.0",
        "Resources:",
        "  - myLambdaFunction:",
        "      Type: AWS::Lambda::Function",
        "      Properties:",
        f'        Name: "{fn_name}"',
        '        Alias: "live"',
        f'        CurrentVersion: "{current_version}"',
        f'        TargetVersion: "{target_version}"',
    ]
    if hook_function_name:
        lines.append("hooks:")
        lines.append(f'  - BeforeAllowTraffic: "{hook_function_name}"')
    return "\n".join(lines) + "\n"


def _hook_zip(delay_s=0):
    buf = io.BytesIO()
    code = (
        "import time\n"
        "import boto3\n"
        "def handler(event, context):\n"
        f"    time.sleep({delay_s})\n"
        "    client = boto3.client('codedeploy')\n"
        "    client.put_lifecycle_event_hook_execution_status(\n"
        "        deploymentId=event['DeploymentId'],\n"
        "        lifecycleEventHookExecutionId=event['LifecycleEventHookExecutionId'],\n"
        "        status='Succeeded',\n"
        "    )\n"
        "    return {'ok': True}\n"
    )
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _main_zip(payload):
    buf = io.BytesIO()
    code = f"PAYLOAD = {payload!r}\ndef handler(event, context):\n    return {{'ok': True, 'payload': PAYLOAD}}\n"
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-lambdarole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cd"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "codedeploy:PutLifecycleEventHookExecutionStatus", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="PutLifecycleStatus", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="PutLifecycleStatus"))
    return role_arn


def _create_codedeploy_lambda_role(ctx, hook_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cd"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRoleForLambda"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": hook_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="InvokeHook", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="InvokeHook"))
    return role_arn


def _create_function(ctx, lambda_client, fn_name, role_arn, payload, is_zip=False):
    code_bytes = payload if is_zip else _main_zip(payload)
    deadline = time.monotonic() + 30
    while True:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lambda_client.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code_bytes},
                Timeout=30,
                Publish=True,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cd"},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=fn_name))
    _wait_lambda_ready(lambda_client, fn_name)
    return resp["Version"]


def _publish_new_version(lambda_client, fn_name, payload):
    lambda_client.update_function_code(FunctionName=fn_name, ZipFile=_main_zip(payload))
    _wait_lambda_ready(lambda_client, fn_name)
    version = lambda_client.publish_version(FunctionName=fn_name)["Version"]
    _wait_lambda_ready(lambda_client, fn_name)
    return version


def _wait_lambda_ready(lambda_client, fn_name, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lambda_client.get_function_configuration(FunctionName=fn_name)
        if cfg.get("State", "Active") == "Active" and cfg.get("LastUpdateStatus", "Successful") == "Successful":
            return
        time.sleep(2)
    raise AssertionError(f"lambda function {fn_name} never became ready within {timeout_s}s")


def _fn_arn(lambda_client, fn_name):
    return lambda_client.get_function_configuration(FunctionName=fn_name)["FunctionArn"]


def _create_lambda_deployment_group(ctx, cd, app, group, service_role_arn):
    deadline = time.monotonic() + 30
    while True:
        try:
            group_id = cd.create_deployment_group(
                applicationName=app,
                deploymentGroupName=group,
                serviceRoleArn=service_role_arn,
                deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
                deploymentStyle={"deploymentType": "BLUE_GREEN", "deploymentOption": "WITH_TRAFFIC_CONTROL"},
                tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cd"}],
            )["deploymentGroupId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=group))
    return group_id


def _create_deployment_with_retry(cd, app_name, dg_name, revision, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cd.create_deployment(
                applicationName=app_name, deploymentGroupName=dg_name, revision=revision
            )["deploymentId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _wait_deployment_status(cd, deployment_id, target_statuses, timeout_s=150.0, interval_s=1.5):
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

