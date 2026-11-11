"""cli-apigateway-missing-lambda-permission-rejected."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cli-apigateway-missing-lambda-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_MARKER = "sim2realpermcheckok"
_LOG_MARKER = f"TAG{_MARKER}"


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Negative: an AWS_PROXY integration without a matching lambda:InvokeFunction resource
    policy statement cannot invoke the Lambda (500, no execution) — and adding the permission
    afterwards (positive control, same API) makes the identical invoke succeed."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    region = ctx.region
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    role_arn, role_name = _create_lambda_role(
        ctx, ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    )

    func_name = ctx.unique_name("sim2real-behav-fn-")
    code = (
        "import json\n\n"
        "def handler(event, context):\n"
        f"    print('{_LOG_MARKER}')\n"
        "    return {\n"
        "        'statusCode': 200,\n"
        f"        'body': json.dumps({{'marker': '{_MARKER}'}}),\n"
        "    }\n"
    )
    _create_lambda_function_cli(ctx, func_name, role_arn, _lambda_zip_bytes(code))
    log_group_name = f"/aws/lambda/{func_name}"
    ctx.on_cleanup(lambda: _run_aws(ctx, "lambda", "delete-function", "--function-name", func_name, check=False))
    ctx.on_cleanup(lambda: _run_aws(ctx, "logs", "delete-log-group", "--log-group-name", log_group_name, check=False))
    fn_cfg = _wait_lambda_active(ctx, func_name)
    fn_arn = fn_cfg["FunctionArn"]

    api_name = ctx.unique_name("sim2real-behav-api-")
    api = _run_aws(ctx, "apigateway", "create-rest-api", "--name", api_name)
    api_id = api["id"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "apigateway", "delete-rest-api", "--rest-api-id", api_id, check=False))

    resources = _run_aws(ctx, "apigateway", "get-resources", "--rest-api-id", api_id)
    root_id = [r["id"] for r in resources["items"] if r["path"] == "/"][0]
    resource = _run_aws(
        ctx, "apigateway", "create-resource",
        "--rest-api-id", api_id, "--parent-id", root_id, "--path-part", "echo",
    )
    resource_id = resource["id"]
    _run_aws(
        ctx, "apigateway", "put-method",
        "--rest-api-id", api_id, "--resource-id", resource_id,
        "--http-method", "GET", "--authorization-type", "NONE",
    )
    integration_uri = f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations"
    _run_aws(
        ctx, "apigateway", "put-integration",
        "--rest-api-id", api_id, "--resource-id", resource_id, "--http-method", "GET",
        "--type", "AWS_PROXY", "--integration-http-method", "POST", "--uri", integration_uri,
    )
    _run_aws(ctx, "apigateway", "create-deployment", "--rest-api-id", api_id, "--stage-name", "test")

    # NEGATIVE: no lambda:InvokeFunction permission granted to apigateway yet.
    denied_result = _run_aws(
        ctx, "apigateway", "test-invoke-method",
        "--rest-api-id", api_id, "--resource-id", resource_id, "--http-method", "GET",
    )
    assert denied_result["status"] == 500, f"expected 500 without permission, got {denied_result}"
    assert _MARKER not in denied_result.get("body", ""), "lambda body leaked despite missing permission"
    assert not _poll_for_log_marker(ctx, log_group_name, _LOG_MARKER, timeout_s=20.0), (
        "lambda was actually executed despite missing invoke permission"
    )

    # POSITIVE CONTROL: grant the permission, the identical call now succeeds and executes.
    source_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/GET/echo"
    _run_aws(
        ctx, "lambda", "add-permission",
        "--function-name", func_name, "--statement-id", "apigw-invoke",
        "--action", "lambda:InvokeFunction", "--principal", "apigateway.amazonaws.com",
        "--source-arn", source_arn,
    )
    allowed_result = _wait_for_permission_effective(ctx, api_id, resource_id)
    assert allowed_result["status"] == 200, f"expected 200 after granting permission, got {allowed_result}"
    assert _MARKER in allowed_result["body"], "lambda marker missing after permission was granted"
    assert _poll_for_log_marker(ctx, log_group_name, _LOG_MARKER, timeout_s=60.0), (
        "lambda execution log never appeared after permission was granted"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env,
        capture_output=True, text=True, timeout=timeout_s, cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _lambda_zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_arns):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]

    def _cleanup():
        try:
            for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    return role["Arn"], role_name


def _create_lambda_function_cli(ctx, name, role_arn, zip_bytes, handler="lambda_function.handler", env=None, timeout_s=120.0):
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(zip_bytes)
        zip_path = f.name
    try:
        args = [
            "lambda", "create-function", "--function-name", name, "--runtime", "python3.12",
            "--role", role_arn, "--handler", handler, "--zip-file", f"fileb://{zip_path}", "--timeout", "30",
        ]
        if env:
            args += ["--environment", json.dumps({"Variables": env})]
        deadline = time.monotonic() + timeout_s
        last_err = ""
        while time.monotonic() < deadline:
            proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=30.0, check=False)
            if proc.returncode == 0:
                return
            last_err = proc.stderr
            if "InvalidParameterValueException" in proc.stderr or "cannot be assumed" in proc.stderr:
                time.sleep(3)
                continue
            raise AssertionError(f"create-function failed: {proc.stderr[-500:]}")
        raise AssertionError(f"create-function never succeeded (role propagation timeout): {last_err[-500:]}")
    finally:
        os.unlink(zip_path)


def _wait_lambda_active(ctx, name, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = _run_aws(ctx, "lambda", "get-function-configuration", "--function-name", name)
        if cfg.get("State") == "Active":
            return cfg
        time.sleep(2)
    raise AssertionError(f"Lambda {name} never became Active within {timeout_s}s")


def _poll_for_log_marker(ctx, log_group_name, marker_text, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = _run_aws(
            ctx, "logs", "filter-log-events",
            "--log-group-name", log_group_name, "--filter-pattern", marker_text,
            check=False,
        )
        if isinstance(result, dict) and result.get("events"):
            for evt in result["events"]:
                if marker_text in evt.get("message", ""):
                    return True
        time.sleep(4)
    return False


def _wait_for_permission_effective(ctx, api_id, resource_id, timeout_s=30.0):
    """IAM/resource-policy propagation for a freshly added Lambda permission can lag briefly;
    poll test-invoke-method until it stops returning 500."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _run_aws(
            ctx, "apigateway", "test-invoke-method",
            "--rest-api-id", api_id, "--resource-id", resource_id, "--http-method", "GET",
        )
        if last["status"] == 200:
            return last
        time.sleep(2)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
