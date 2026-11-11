"""cli-apigateway-lambda-integration-setup-and-test."""
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

CHECK = "cli-apigateway-lambda-integration-setup-and-test"
GROUP = "cli-roundtrip"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CLI put-integration wiring POST to a Lambda (AWS_PROXY) describes as pointing at that function,
    and invoking the deployed endpoint makes the Lambda process (uppercase) and log the JSON body."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    region = ctx.region
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    code = (
        "import json\n"
        "def handler(event, context):\n"
        "    body = json.loads(event.get('body') or '{}')\n"
        "    text = body.get('text', '')\n"
        "    print('PROCESSED:' + text)\n"
        "    return {'statusCode': 200, 'headers': {'Content-Type': 'application/json'},"
        " 'body': json.dumps({'upper': text.upper()})}\n"
    )
    fn = _create_lambda_function(ctx, code)
    log_group = f"/aws/lambda/{fn['name']}"

    api = _run_aws(
        ctx, "apigateway", "create-rest-api", "--name", ctx.unique_name("sim2real-api-"),
        "--tags", "sim2real:managed=true",
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))

    resources = _run_aws(ctx, "apigateway", "get-resources", "--rest-api-id", api_id)
    root_id = next(r["id"] for r in resources["items"] if r["path"] == "/")
    resource = _run_aws(
        ctx, "apigateway", "create-resource", "--rest-api-id", api_id,
        "--parent-id", root_id, "--path-part", "process",
    )
    resource_id = resource["id"]
    _run_aws(
        ctx, "apigateway", "put-method", "--rest-api-id", api_id, "--resource-id", resource_id,
        "--http-method", "POST", "--authorization-type", "NONE",
    )
    integration_uri = (
        f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{fn['arn']}/invocations"
    )
    _run_aws(
        ctx, "apigateway", "put-integration", "--rest-api-id", api_id, "--resource-id", resource_id,
        "--http-method", "POST", "--type", "AWS_PROXY", "--integration-http-method", "POST",
        "--uri", integration_uri,
    )

    # Verify the wiring itself via a describe (SDK), not just that the put succeeded.
    integration = ctx.client("apigateway").get_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST",
    )
    assert integration["type"] == "AWS_PROXY", f"expected AWS_PROXY, got {integration['type']}"
    assert integration["uri"] == integration_uri, (
        f"expected integration uri {integration_uri!r}, got {integration['uri']!r}"
    )
    assert fn["arn"] in integration["uri"], f"lambda arn {fn['arn']!r} missing from {integration['uri']!r}"

    source_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/POST/process"
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"], StatementId="apigw-invoke", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com", SourceArn=source_arn,
    )
    deployment = _run_aws(
        ctx, "apigateway", "create-deployment", "--rest-api-id", api_id, "--stage-name", "live",
    )
    assert deployment["id"], f"create-deployment returned no id: {deployment}"

    invoke_url = f"{ctx.rest_api_url(api_id, 'live')}/process"
    status, body_text = _poll_http_post(invoke_url, {"text": "hello"}, timeout_s=45.0)
    assert status == 200, f"unexpected status {status}: {body_text}"
    assert json.loads(body_text) == {"upper": "HELLO"}, f"unexpected response body: {body_text}"

    assert _wait_for_log_marker(ctx, log_group, "PROCESSED:hello", timeout_s=60.0), (
        "Lambda never processed the POST body -- integration may not be forwarding it"
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags={"sim2real:managed": "true"},
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


def _poll_http_post(url: str, payload: dict, timeout_s=45.0, interval_s=3.0):
    data = json.dumps(payload).encode()
    deadline = time.monotonic() + timeout_s
    last = (None, "")
    while time.monotonic() < deadline:
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
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
