"""cli-lambda-invoke-missing-permission-negative."""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import tempfile
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-lambda-invoke-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Invoke from an assumed-role session with no lambda permissions is refused with AccessDeniedException
    and the function never runs; the same Invoke from the full-permission caller runs it (positive control)."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    code = (
        "def handler(event, context):\n"
        "    print('INVOKED:' + str(event.get('marker', '')))\n"
        "    return {'ok': True}\n"
    )
    fn = _create_lambda_function(ctx, code)
    log_group = f"/aws/lambda/{fn['name']}"

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    iam = ctx.client("iam")
    restricted_role_name = ctx.unique_name("sim2real-restricted-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=restricted_role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    restricted_role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=restricted_role_name))
    # Deliberately grant NO lambda permissions -- only an unrelated read-only action, so the
    # role has some real (but irrelevant) permission and Invoke is denied purely by omission.
    minimal_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=restricted_role_name, PolicyName="minimal", PolicyDocument=json.dumps(minimal_policy),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=restricted_role_name, PolicyName="minimal"))

    restricted_creds = None
    for _ in range(15):
        try:
            restricted_creds = sts.assume_role(
                RoleArn=restricted_role_arn, RoleSessionName="sim2real-restricted-session",
            )["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            time.sleep(2)
    if restricted_creds is None:
        raise AssertionError("could never assume the restricted role (IAM propagation never settled)")

    restricted_env = {
        "AWS_ACCESS_KEY_ID": restricted_creds["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": restricted_creds["SecretAccessKey"],
        "AWS_SESSION_TOKEN": restricted_creds["SessionToken"],
    }

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        denied_out_path = f.name
    denied_in_path = denied_out_path + ".in"
    with open(denied_in_path, "w") as f:
        f.write(json.dumps({"marker": "DENIED-CALL"}))
    try:
        # fileb:// loads raw bytes from disk and lets the CLI handle base64 encoding itself --
        # this works unmodified on both CLI v1 and v2, unlike passing the JSON literal directly
        # on the command line (which the AWS CLI v2 default cli_binary_format rejects as invalid
        # base64).
        proc = _run_shell(
            ctx,
            [
                "aws", "--output", "json", "lambda", "invoke",
                "--function-name", fn["name"],
                "--payload", f"fileb://{denied_in_path}", denied_out_path,
            ],
            env_extra=restricted_env, check=False, timeout_s=30.0,
        )
    finally:
        if os.path.exists(denied_out_path):
            os.unlink(denied_out_path)
        if os.path.exists(denied_in_path):
            os.unlink(denied_in_path)
    assert proc.returncode != 0, "CLI invoke with no lambda permissions unexpectedly succeeded"
    match = re.search(r"An error occurred \(([A-Za-z]+)\)", proc.stderr)
    assert match is not None, f"could not find AWS error code in stderr: {proc.stderr}"
    assert match.group(1) == "AccessDeniedException", (
        f"expected AccessDeniedException, CLI reported {match.group(1)!r} (stderr: {proc.stderr})"
    )
    assert not _log_has_marker(ctx, log_group, "INVOKED:DENIED-CALL"), (
        "function executed despite the caller lacking lambda:InvokeFunction"
    )

    # Positive control: the same CLI invoke with full-permission credentials succeeds and executes.
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        allowed_out_path = f.name
    allowed_in_path = allowed_out_path + ".in"
    with open(allowed_in_path, "w") as f:
        f.write(json.dumps({"marker": "ALLOWED-CALL"}))
    try:
        _run_shell(
            ctx,
            [
                "aws", "--output", "json", "lambda", "invoke",
                "--function-name", fn["name"],
                "--payload", f"fileb://{allowed_in_path}", allowed_out_path,
            ],
            timeout_s=30.0,
        )
        with open(allowed_out_path) as fh:
            allowed_payload = json.load(fh)
    finally:
        os.unlink(allowed_out_path)
        os.unlink(allowed_in_path)
    assert allowed_payload == {"ok": True}, (
        f"expected the handler's own return value {{'ok': True}}, CLI invoke returned {allowed_payload!r}"
    )
    assert _wait_for_log_marker(ctx, log_group, "INVOKED:ALLOWED-CALL", timeout_s=60.0), (
        "control invocation with full permissions never executed -- mechanism itself is broken"
    )


# ===== helpers =====


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env, capture_output=True,
        text=True, timeout=timeout_s, cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lmbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_lambda_function(ctx, code: str, env_vars=None, handler="lambda_function.handler", timeout=10) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_lambda_role(ctx)
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(code)
    resp = None
    last_err = None
    for _ in range(15):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler=handler,
                Code={"ZipFile": zip_bytes}, Timeout=timeout, Environment={"Variables": env_vars or {}},
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while lam.get_function(FunctionName=name)["Configuration"]["State"] != "Active":
        if time.monotonic() >= deadline:
            raise AssertionError("lambda function never became Active")
        time.sleep(2)
    return {"name": name, "arn": resp["FunctionArn"]}


def _log_has_marker(ctx, log_group: str, marker: str) -> bool:
    logs = ctx.client("logs")
    try:
        resp = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')
    except logs.exceptions.ResourceNotFoundException:
        return False
    return bool(resp.get("events"))


def _wait_for_log_marker(ctx, log_group: str, marker: str, timeout_s=60.0, interval_s=3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _log_has_marker(ctx, log_group, marker):
            return True
        time.sleep(interval_s)
    return False


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
