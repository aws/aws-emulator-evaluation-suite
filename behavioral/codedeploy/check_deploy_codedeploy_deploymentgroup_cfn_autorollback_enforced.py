"""deploy-codedeploy-deploymentgroup-cfn-autorollback-enforced."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codedeploy-deploymentgroup-cfn-autorollback-enforced"
GROUP = "deploy"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation deployment group with auto-rollback on DEPLOYMENT_FAILURE answers a failed
    BeforeAllowTraffic hook with a rollback deployment that Succeeded, restores the alias to v2 and is
    the group's lastSuccessfulDeployment."""
    lambda_client = ctx.client("lambda")
    cd = ctx.client("codedeploy")
    cfn = ctx.client("cloudformation")

    exec_role_arn = _create_lambda_execution_role(ctx)

    fn_name = ctx.unique_name("sim2real-cd-fn-")
    v1 = _create_function(ctx, lambda_client, fn_name, exec_role_arn, b"payload-v1")
    lambda_client.create_alias(FunctionName=fn_name, Name="live", FunctionVersion=v1)
    v2 = _publish_new_version(lambda_client, fn_name, b"payload-v2")

    hook_name = ctx.unique_name("sim2real-cd-hook-")
    _create_function(ctx, lambda_client, fn_name=hook_name, role_arn=exec_role_arn, payload=_hook_zip(), is_zip=True)
    hook_arn = _fn_arn(lambda_client, hook_name)

    # Create (and prove usable against the real CodeDeploy control plane) the
    # CodeDeploy service role OUTSIDE of CloudFormation. Creating it inside the same
    # stack as the DeploymentGroup races IAM's eventual-consistency propagation
    # window against CloudFormation (which does not retry), causing a spurious
    # ROLLBACK_COMPLETE that has nothing to do with the behavior under test.
    service_role_arn = _create_codedeploy_lambda_role(ctx, hook_arn)
    _wait_role_usable_by_codedeploy(ctx, cd, service_role_arn)

    outputs = _deploy_cfn(ctx, cfn, _template(), {"ServiceRoleArn": service_role_arn})
    app_name = outputs["ApplicationName"]
    dg_name = outputs["DeploymentGroupName"]

    # First deployment: plain version shift v1 -> v2, no hooks -> must succeed. This
    # becomes the "last successful revision" that a later rollback should redeploy.
    content1 = _appspec(fn_name, v1, v2)
    revision1 = {"revisionType": "AppSpecContent", "appSpecContent": {"content": content1}}
    dep1_id = _create_deployment_with_retry(cd, app_name, dg_name, revision1)
    dep1 = _wait_deployment_status(cd, dep1_id, {"Succeeded", "Failed", "Stopped"}, timeout_s=180)
    assert dep1["status"] == "Succeeded", dep1

    # Second deployment: v2 -> v3, with a BeforeAllowTraffic hook that always reports
    # Failed -> the deployment must fail, and auto-rollback must kick in.
    v3 = _publish_new_version(lambda_client, fn_name, b"payload-v3")
    content2 = _appspec(fn_name, v2, v3, hook_function_name=hook_name)
    revision2 = {"revisionType": "AppSpecContent", "appSpecContent": {"content": content2}}
    dep2_id = _create_deployment_with_retry(cd, app_name, dg_name, revision2)
    dep2 = _wait_deployment_status(cd, dep2_id, {"Succeeded", "Failed", "Stopped"}, timeout_s=180)
    assert dep2["status"] == "Failed", dep2

    rollback_id = dep2.get("rollbackInfo", {}).get("rollbackDeploymentId")
    assert rollback_id, f"no automatic rollback deployment recorded on failed deployment: {dep2}"

    rollback = _wait_deployment_status(cd, rollback_id, {"Succeeded", "Failed", "Stopped"}, timeout_s=180)
    assert rollback["status"] == "Succeeded", rollback

    # The rollback deployment must actually redeploy the last-successful state: dep1
    # successfully shifted the "live" alias to v2, so an automatic rollback of the
    # failed v2->v3 attempt must land the alias back at v2 (the last *successful*
    # target), not just verify a stack/deployment status.
    alias = lambda_client.get_alias(FunctionName=fn_name, Name="live")
    assert alias["FunctionVersion"] == v2, alias


    group_info = cd.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)["deploymentGroupInfo"]
    assert group_info["lastSuccessfulDeployment"]["deploymentId"] == rollback_id, group_info["lastSuccessfulDeployment"]


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


def _hook_zip():
    buf = io.BytesIO()
    code = (
        "import boto3\n"
        "def handler(event, context):\n"
        "    client = boto3.client('codedeploy')\n"
        "    client.put_lifecycle_event_hook_execution_status(\n"
        "        deploymentId=event['DeploymentId'],\n"
        "        lifecycleEventHookExecutionId=event['LifecycleEventHookExecutionId'],\n"
        "        status='Failed',\n"
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
    iam.put_role_policy(
        RoleName=role_name, PolicyName="PutLifecycleStatus", PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="PutLifecycleStatus"))
    return role_arn


def _create_codedeploy_lambda_role(ctx, hook_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
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


def _wait_role_usable_by_codedeploy(ctx, cd, service_role_arn, timeout_s=90.0):
    """Prove the freshly-created service role has propagated through IAM and is
    accepted by the CodeDeploy control plane, by cycling a throwaway application +
    deployment group through it (with the standard InvalidRoleException retry)."""
    probe_app = ctx.unique_name("sim2real-cd-roleprobe-")
    cd.create_application(applicationName=probe_app, computePlatform="Lambda")
    try:
        probe_group = ctx.unique_name("sim2real-cd-roleprobe-dg-")
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                cd.create_deployment_group(
                    applicationName=probe_app,
                    deploymentGroupName=probe_group,
                    serviceRoleArn=service_role_arn,
                    deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
                    deploymentStyle={"deploymentType": "BLUE_GREEN", "deploymentOption": "WITH_TRAFFIC_CONTROL"},
                )
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() > deadline:
                    raise
                time.sleep(3)
        cd.delete_deployment_group(applicationName=probe_app, deploymentGroupName=probe_group)
    finally:
        cd.delete_application(applicationName=probe_app)


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
                Timeout=15,
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


def _template():
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"ServiceRoleArn": {"Type": "String"}},
        "Resources": {
            "CDApplication": {"Type": "AWS::CodeDeploy::Application", "Properties": {"ComputePlatform": "Lambda"}},
            "CDDeploymentGroup": {
                "Type": "AWS::CodeDeploy::DeploymentGroup",
                "Properties": {
                    "ApplicationName": {"Ref": "CDApplication"},
                    "ServiceRoleArn": {"Ref": "ServiceRoleArn"},
                    "DeploymentConfigName": "CodeDeployDefault.LambdaAllAtOnce",
                    "DeploymentStyle": {"DeploymentType": "BLUE_GREEN", "DeploymentOption": "WITH_TRAFFIC_CONTROL"},
                    "AutoRollbackConfiguration": {"Enabled": True, "Events": ["DEPLOYMENT_FAILURE"]},
                },
            },
        },
        "Outputs": {
            "ApplicationName": {"Value": {"Ref": "CDApplication"}},
            "DeploymentGroupName": {"Value": {"Ref": "CDDeploymentGroup"}},
        },
    }


def _deploy_cfn(ctx, cfn, template, parameters):
    stack_name = ctx.unique_name("sim2real-cd-rbstack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _delete_stack(cfn, stack_name):
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


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


def _wait_deployment_status(cd, deployment_id, target_statuses, timeout_s=150.0, interval_s=3.0):
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
