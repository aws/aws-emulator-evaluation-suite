"""cli-rotate-secret-and-verify-version-stages."""
from __future__ import annotations

import io
import json
import subprocess
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-rotate-secret-and-verify-version-stages"
GROUP = "cli-workflow"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws secretsmanager rotate-secret drives a real rotation Lambda through
    createSecret/setSecret/testSecret/finishSecret; the AWSPENDING version is
    correctly promoted to AWSCURRENT and the old version demoted to AWSPREVIOUS."""
    require_tools("aws")

    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-rot-secret-")
    initial_value = "before-rotation-" + ctx.unique_name("")

    created = sm.create_secret(
        Name=secret_name,
        SecretString=initial_value,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    initial_version_id = created["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    # Resource "*" (not the specific secret ARN): Secrets Manager's own IAM authorization
    # check for a rotation Lambda role is more reliable against a wildcard resource than a
    # single literal secret ARN across the createSecret/setSecret/testSecret/finishSecret
    # sequence of calls the rotation backend drives.
    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:UpdateSecretVersionStage",
                    "secretsmanager:GetRandomPassword",
                ],
                "Resource": "*",
            }
        ],
    )

    handler_code = _ROTATION_HANDLER
    fn_name = _create_function(ctx, role_arn, handler_code, timeout=60)

    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="allowSecretsManagerInvoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceAccount=account_id,
    )
    fn_arn = lam.get_function(FunctionName=fn_name)["Configuration"]["FunctionArn"]

    _run_aws(
        ctx,
        "secretsmanager",
        "rotate-secret",
        "--secret-id",
        secret_arn,
        "--rotation-lambda-arn",
        fn_arn,
        "--rotation-rules",
        "AutomaticallyAfterDays=30",
    )

    def _rotation_complete():
        meta = sm.describe_secret(SecretId=secret_arn)
        stages = meta.get("VersionIdsToStages", {})
        # AWSPENDING is NOT automatically stripped from the version that becomes AWSCURRENT —
        # real Secrets Manager leaves it attached until the *next* rotation begins. So
        # completion is "AWSCURRENT moved to a version other than the original", not "no
        # version is AWSPENDING".
        current = [v for v, s in stages.items() if "AWSCURRENT" in s]
        moved = bool(current) and current[0] != initial_version_id
        return moved, stages

    deadline = time.monotonic() + 150.0
    stages = {}
    while time.monotonic() < deadline:
        done, stages = _rotation_complete()
        if done:
            break
        time.sleep(3)
    else:
        raise AssertionError(f"rotation never completed (AWSCURRENT still on original version): {stages}")

    current_version = [v for v, s in stages.items() if "AWSCURRENT" in s][0]
    assert current_version != initial_version_id, "AWSCURRENT never moved off the original version"
    assert "AWSPREVIOUS" in stages.get(initial_version_id, []), stages

    new_value = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]
    assert new_value != initial_value, "rotated value equals the pre-rotation value"


_ROTATION_HANDLER = """
import boto3

def handler(event, context):
    service_client = boto3.client('secretsmanager')
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    metadata = service_client.describe_secret(SecretId=arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        raise ValueError("no stage for token %s" % token)
    if 'AWSCURRENT' in versions[token]:
        return
    elif 'AWSPENDING' not in versions[token]:
        raise ValueError("token %s not AWSPENDING" % token)

    if step == 'createSecret':
        try:
            service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage='AWSPENDING')
        except service_client.exceptions.ResourceNotFoundException:
            new_value = 'rotated-' + token[:12]
            service_client.put_secret_value(
                SecretId=arn, ClientRequestToken=token,
                SecretString=new_value, VersionStages=['AWSPENDING'],
            )
    elif step == 'setSecret':
        pass
    elif step == 'testSecret':
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage='AWSPENDING')
    elif step == 'finishSecret':
        current_version = None
        for version, stages in metadata['VersionIdsToStages'].items():
            if 'AWSCURRENT' in stages:
                if version == token:
                    return
                current_version = version
                break
        service_client.update_secret_version_stage(
            SecretId=arn, VersionStage='AWSCURRENT',
            MoveToVersionId=token, RemoveFromVersionId=current_version,
        )
    else:
        raise ValueError('invalid step %s' % step)
"""


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _make_zip(handler_code: str, filename="index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_statements, role_name=None):
    iam = ctx.client("iam")
    role_name = role_name or ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    if policy_statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_function(ctx, role_arn, handler_code, handler="index.handler", env_vars=None, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(handler_code)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=False,
        Tags={"sim2real": CHECK},
    )
    if env_vars:
        kwargs["Environment"] = {"Variables": env_vars}
    last_err = None
    for _ in range(8):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_for_active(ctx, name)
    return name


def _wait_for_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


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
