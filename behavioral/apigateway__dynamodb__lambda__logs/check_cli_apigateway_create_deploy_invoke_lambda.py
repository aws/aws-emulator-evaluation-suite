"""cli-apigateway-create-deploy-invoke-lambda."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cli-apigateway-create-deploy-invoke-lambda"
GROUP = "cli-roundtrip"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_MARKER = "sim2real-apigw-lambda-ok"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CLI: create REST API, wire AWS_PROXY integration to a Lambda, deploy, and invoke it —
    the API Gateway route must actually reach and execute the Lambda function."""
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
        "    return {\n"
        "        'statusCode': 200,\n"
        f"        'body': json.dumps({{'marker': '{_MARKER}', 'path': event.get('path')}}),\n"
        "    }\n"
    )
    _create_lambda_function_cli(ctx, func_name, role_arn, _lambda_zip_bytes(code))
    ctx.on_cleanup(lambda: _run_aws(ctx, "lambda", "delete-function", "--function-name", func_name, check=False))
    fn_cfg = _wait_lambda_active(ctx, func_name)
    fn_arn = fn_cfg["FunctionArn"]

    api_name = ctx.unique_name("sim2real-behav-api-")
    api = _run_aws(ctx, "apigateway", "create-rest-api", "--name", api_name, "--tags", "sim2real:managed=true")
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

    stage_name = "test"
    source_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/GET/echo"
    _run_aws(
        ctx, "lambda", "add-permission",
        "--function-name", func_name, "--statement-id", "apigw-invoke",
        "--action", "lambda:InvokeFunction", "--principal", "apigateway.amazonaws.com",
        "--source-arn", source_arn,
    )

    deployment = _run_aws(ctx, "apigateway", "create-deployment", "--rest-api-id", api_id, "--stage-name", stage_name)
    assert deployment["id"], f"create-deployment returned no id: {deployment}"

    result = _run_aws(
        ctx, "apigateway", "test-invoke-method",
        "--rest-api-id", api_id, "--resource-id", resource_id, "--http-method", "GET",
    )
    assert result["status"] == 200, f"unexpected integration status: {result}"
    assert _MARKER in result["body"], f"lambda marker missing from response body: {result['body']}"

    # test-invoke-method simulates the integration directly and never requires a deployment to
    # exist, so it cannot tell "deployed and serving" from "never deployed" -- only a real call
    # against the deployed stage's own invoke URL proves create-deployment did something.
    invoke_url = f"{ctx.rest_api_url(api_id, stage_name)}/echo"
    status, body_text = _poll_http_ok(ctx, invoke_url, timeout_s=45.0)
    assert status == 200, f"deployed stage endpoint returned unexpected status {status}: {body_text}"
    assert _MARKER in body_text, f"lambda marker missing from deployed endpoint response: {body_text}"


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]

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
            "--tags", "sim2real:managed=true",
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


def _poll_http_ok(ctx, url, timeout_s=45.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = (None, "")
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            last = (exc.code, exc.read().decode())
        except urllib.error.URLError:
            last = (None, "network error")
        time.sleep(interval_s)
    return last


def _wait_lambda_active(ctx, name, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = _run_aws(ctx, "lambda", "get-function-configuration", "--function-name", name)
        if cfg.get("State") == "Active":
            return cfg
        time.sleep(2)
    raise AssertionError(f"Lambda {name} never became Active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
