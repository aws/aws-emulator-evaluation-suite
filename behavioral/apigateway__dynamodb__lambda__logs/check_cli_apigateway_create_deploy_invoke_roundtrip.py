"""cli-apigateway-create-deploy-invoke-roundtrip."""
from __future__ import annotations

import io
import json
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cli-apigateway-create-deploy-invoke-roundtrip"
GROUP = "cli-roundtrip"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CLI-driven REST API creation + Lambda integration + deployment; the invoked endpoint
    actually executes the Lambda function (proven via CloudWatch-visible marker) and the
    response body reflects the function's real output, cross-checked against SDK describes."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    region = ctx.region
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    code = (
        "import json\n"
        "def handler(event, context):\n"
        "    qs = event.get('queryStringParameters') or {}\n"
        "    token = qs.get('token', 'none')\n"
        "    print('MARKER:' + token)\n"
        "    return {'statusCode': 200, 'headers': {'Content-Type': 'application/json'},"
        " 'body': json.dumps({'echo': token})}\n"
    )
    fn = _create_lambda_function(ctx, code)

    api = _run_aws(
        ctx, "apigateway", "create-rest-api", "--name", ctx.unique_name("sim2real-api-"),
        "--tags", f"sim2real={CHECK}",
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))

    resources = _run_aws(ctx, "apigateway", "get-resources", "--rest-api-id", api_id)
    root_id = next(r["id"] for r in resources["items"] if r["path"] == "/")

    resource = _run_aws(
        ctx, "apigateway", "create-resource", "--rest-api-id", api_id,
        "--parent-id", root_id, "--path-part", "echo",
    )
    resource_id = resource["id"]

    _run_aws(
        ctx, "apigateway", "put-method", "--rest-api-id", api_id, "--resource-id", resource_id,
        "--http-method", "GET", "--authorization-type", "NONE",
    )

    integration_uri = (
        f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{fn['arn']}/invocations"
    )
    _run_aws(
        ctx, "apigateway", "put-integration", "--rest-api-id", api_id, "--resource-id", resource_id,
        "--http-method", "GET", "--type", "AWS_PROXY", "--integration-http-method", "POST",
        "--uri", integration_uri,
    )

    source_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/GET/echo"
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )

    deployment = _run_aws(
        ctx, "apigateway", "create-deployment", "--rest-api-id", api_id, "--stage-name", "test",
    )
    assert deployment["id"], f"create-deployment returned no deployment id: {deployment}"

    stage = ctx.client("apigateway").get_stage(restApiId=api_id, stageName="test")
    assert stage["deploymentId"] == deployment["id"], (
        f"stage 'test' points at deployment {stage['deploymentId']!r}, "
        f"expected the one just created {deployment['id']!r}"
    )

    invoke_url = f"{ctx.rest_api_url(api_id, 'test')}/echo?token=roundtrip-marker"
    status, body_text = _poll_http_ok(invoke_url, timeout_s=45.0)
    assert status == 200, f"unexpected status {status}: {body_text}"
    body = json.loads(body_text)
    assert body == {"echo": "roundtrip-marker"}, f"unexpected response body: {body!r}"

    log_group = f"/aws/lambda/{fn['name']}"
    assert _wait_for_log_marker(ctx, log_group, "MARKER:roundtrip-marker", timeout_s=60.0), (
        "Lambda invocation marker never appeared in CloudWatch Logs -- endpoint response "
        "may not reflect a real Lambda execution"
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


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


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


def _wait_for_log_marker(ctx, log_group: str, marker: str, timeout_s=60.0, interval_s=3.0) -> bool:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')
            if resp.get("events"):
                return True
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(interval_s)
    return False


def _poll_http_ok(url: str, timeout_s=45.0, interval_s=3.0):
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
