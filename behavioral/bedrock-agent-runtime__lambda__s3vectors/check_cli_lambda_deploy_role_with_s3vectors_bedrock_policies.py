"""cli-lambda-deploy-role-with-s3vectors-bedrock-policies."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-lambda-deploy-role-with-s3vectors-bedrock-policies"
GROUP = "cli-script"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CLI-built role with s3vectors and bedrock inline policies authorizes a Lambda on both.

    Probes on nonexistent ids return the exact not-found errors, not AccessDeniedException."""
    require_tools("aws")

    role_name = ctx.unique_name("sim2real-dual-role-")
    trust_path = _write_temp_json({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    s3v_policy_path = _write_temp_json({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3vectors:GetIndex", "s3vectors:QueryVectors"], "Resource": "*"}],
    })
    bedrock_policy_path = _write_temp_json({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["bedrock:InvokeAgent"], "Resource": "*"}],
    })
    # Registered before the script runs: a script that fails part-way still leaves the role.
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    try:
        script = f"""
aws iam create-role --role-name {role_name} --assume-role-policy-document file://{trust_path} --tags Key=sim2real:managed,Value=true >/dev/null
aws iam attach-role-policy --role-name {role_name} --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam put-role-policy --role-name {role_name} --policy-name s3vectors-access --policy-document file://{s3v_policy_path}
aws iam put-role-policy --role-name {role_name} --policy-name bedrock-agent-access --policy-document file://{bedrock_policy_path}
aws iam get-role --role-name {role_name} --query 'Role.Arn' --output text
"""
        proc = _run_script(ctx, script)
    finally:
        os.unlink(trust_path)
        os.unlink(s3v_policy_path)
        os.unlink(bedrock_policy_path)
    role_arn = proc.stdout.strip().splitlines()[-1]
    assert role_arn.startswith("arn:aws:iam::"), f"unexpected role arn output: {proc.stdout!r}"

    handler_source = (
        "import json\n"
        "import boto3\n"
        "from botocore.exceptions import ClientError\n\n"
        "def handler(event, context):\n"
        "    results = {}\n"
        "    s3v = boto3.client('s3vectors')\n"
        "    try:\n"
        "        s3v.get_index(vectorBucketName='sim2real-nonexistent-probe-bucket', indexName='nonexistent-index')\n"
        "        results['s3vectors'] = 'unexpected-success'\n"
        "    except ClientError as e:\n"
        "        results['s3vectors'] = e.response['Error']['Code']\n"
        "        results['s3vectors_message'] = e.response['Error'].get('Message')\n"
        "    bedrock = boto3.client('bedrock-agent-runtime')\n"
        "    try:\n"
        "        resp = bedrock.invoke_agent(agentId='AAAAAAAAAA', agentAliasId='TSTALIASID',\n"
        "            sessionId='sim2real-probe-session', inputText='hello')\n"
        "        for _ in resp.get('completion', []):\n"
        "            pass\n"
        "        results['bedrock_agent_runtime'] = 'unexpected-success'\n"
        "    except ClientError as e:\n"
        "        results['bedrock_agent_runtime'] = e.response['Error']['Code']\n"
        "        results['bedrock_agent_runtime_message'] = e.response['Error'].get('Message')\n"
        "    return results\n"
    )
    function_name = ctx.unique_name("sim2real-dual-fn-")
    _create_function_cli(ctx, function_name, role_arn, handler_source)

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
    assert "FunctionError" not in resp, f"lambda invocation errored: {resp}"
    body = json.loads(resp["Payload"].read())

    assert body["s3vectors"] == "NotFoundException", (
        f"expected the s3vectors probe to be authorized and fail with NotFoundException, got {body['s3vectors']!r}"
    )
    assert body["bedrock_agent_runtime"] == "ResourceNotFoundException", (
        f"expected the bedrock-agent-runtime probe to be authorized and fail with ResourceNotFoundException, "
        f"got {body['bedrock_agent_runtime']!r}"
    )
    assert body.get("s3vectors_message") == "The specified index could not be found", f"unexpected s3vectors message {body!r}"
    assert body.get("bedrock_agent_runtime_message") == (
        "Failed to retrieve resource because it doesn't exist. "
        "Retry the request with a different resource identifier."
    ), (
        f"unexpected bedrock-agent-runtime message {body!r}"
    )


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


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(ctx, ["bash", script_path], timeout_s=timeout_s, check=check, env_extra=env_extra)
    finally:
        os.unlink(script_path)


def _run_aws_retrying(ctx, args, retry_substrings, timeout_s=90.0, poll_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_stderr = ""
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, ["aws", "--output", "json", *args], check=False, timeout_s=30.0)
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        last_stderr = proc.stderr
        if any(s in proc.stderr for s in retry_substrings):
            time.sleep(poll_s)
            continue
        raise AssertionError(f"aws {' '.join(args)} failed: {last_stderr[-500:]}")
    raise AssertionError(f"aws {' '.join(args)} did not succeed within {timeout_s}s: {last_stderr[-500:]}")


def _write_temp_json(data) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        return f.name


def _zip_from_source(handler_source: str, filename: str = "index.py") -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, handler_source)
    return buf.getvalue()


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function_cli(ctx, function_name, role_arn, handler_source, timeout=30, env_vars=None):
    zip_bytes = _zip_from_source(handler_source)
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(zip_bytes)
        zip_path = f.name
    try:
        args = [
            "lambda", "create-function",
            "--function-name", function_name,
            "--runtime", "python3.12",
            "--role", role_arn,
            "--handler", "index.handler",
            "--timeout", str(timeout),
            "--zip-file", f"fileb://{zip_path}",
            "--tags", "sim2real:managed=true",
        ]
        if env_vars:
            args += ["--environment", json.dumps({"Variables": env_vars})]
        result = _run_aws_retrying(
            ctx, args,
            retry_substrings=["cannot be assumed", "InvalidParameterValueException", "is not authorized"],
            timeout_s=90.0,
        )
    finally:
        os.unlink(zip_path)
    function_arn = result["FunctionArn"]
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=function_name))
    _wait_lambda_active(ctx, function_name)
    return function_arn


def _wait_lambda_active(ctx, function_name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=function_name)["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda function {function_name} never became Active (last state={state})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
