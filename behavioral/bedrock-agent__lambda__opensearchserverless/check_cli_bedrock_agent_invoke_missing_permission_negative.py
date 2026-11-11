"""cli-bedrock-agent-invoke-missing-permission-negative."""
from __future__ import annotations

import io
import json
import os
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-bedrock-agent-invoke-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["bedrock-agent", "lambda", "opensearchserverless"]

# A syntactically valid but never-created agent and alias id: the permission check and the
# resource lookup are told apart by their distinct error codes, with no agent provisioned.
_FAKE_AGENT_ID = "zzzzzzzzz9"
_FAKE_ALIAS_ID = "zzzzzzzz88"


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws lambda invoke` on a Lambda whose role lacks bedrock:InvokeAgent gets AccessDeniedException for a
    nonexistent agent, while an identical Lambda with the permission gets ResourceNotFoundException."""
    require_tools("aws")

    code = (
        "import boto3, uuid\n\n"
        "def handler(event, context):\n"
        "    client = boto3.client('bedrock-agent-runtime')\n"
        "    try:\n"
        "        resp = client.invoke_agent(\n"
        "            agentId=event['agentId'],\n"
        "            agentAliasId=event['agentAliasId'],\n"
        "            sessionId=str(uuid.uuid4()),\n"
        "            inputText=event['inputText'],\n"
        "        )\n"
        "        completion = ''\n"
        "        for ev in resp.get('completion'):\n"
        "            chunk = ev.get('chunk')\n"
        "            if chunk:\n"
        "                completion += chunk['bytes'].decode('utf-8')\n"
        "        return {'ok': True, 'completion': completion}\n"
        "    except Exception as e:\n"
        "        code = getattr(e, 'response', {}).get('Error', {}).get('Code', type(e).__name__)\n"
        "        return {'ok': False, 'code': code}\n"
    )
    payload = {
        "agentId": _FAKE_AGENT_ID,
        "agentAliasId": _FAKE_ALIAS_ID,
        "inputText": "What is 2 + 2? Respond with only the numeral answer.",
    }

    # --- negative: role lacks bedrock:InvokeAgent ---
    neg_role_arn = _create_lambda_role(ctx, extra_statements=None)
    neg_function = ctx.unique_name("sim2real-agent-invoke-deny-")
    _create_function_with_retry(ctx, neg_function, neg_role_arn, _lambda_zip_bytes(code))
    _wait_function_active(ctx, neg_function)

    # --- positive control: identical setup, role HAS bedrock:InvokeAgent ---
    pos_role_arn = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "bedrock:InvokeAgent", "Resource": "*"}]
    )
    pos_function = ctx.unique_name("sim2real-agent-invoke-allow-")
    _create_function_with_retry(ctx, pos_function, pos_role_arn, _lambda_zip_bytes(code))
    _wait_function_active(ctx, pos_function)

    neg_meta, neg_body = _invoke_lambda_cli(ctx, neg_function, payload)
    assert "FunctionError" not in neg_meta, f"unexpected function error: {neg_body}"
    assert neg_body.get("ok") is False, f"expected the denied role to be rejected, got: {neg_body}"
    assert neg_body.get("code") == "AccessDeniedException", (
        f"expected AccessDeniedException for the role lacking bedrock:InvokeAgent, "
        f"got {neg_body.get('code')} ({neg_body})"
    )
    assert "completion" not in neg_body, f"agent completion leaked despite denied permission: {neg_body}"

    pos_meta, pos_body = _invoke_lambda_cli(ctx, pos_function, payload)
    assert "FunctionError" not in pos_meta, f"unexpected function error: {pos_body}"
    assert pos_body.get("ok") is False, (
        f"expected the nonexistent agent/alias to be rejected at the resource layer, got: {pos_body}"
    )
    assert pos_body.get("code") == "ResourceNotFoundException", (
        f"expected the permission check to pass (role HAS bedrock:InvokeAgent) and hit "
        f"ResourceNotFoundException for the nonexistent agent, got {pos_body.get('code')} ({pos_body})"
    )
    assert "completion" not in pos_body, f"agent completion leaked for a nonexistent agent: {pos_body}"


import subprocess
import tempfile

from botocore.exceptions import ClientError


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


def _lambda_zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, extra_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ]
    if extra_statements:
        statements.extend(extra_statements)
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_function_with_retry(
    ctx, function_name, role_arn, code_bytes, handler="index.handler", env=None, timeout_s=90.0
):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": code_bytes},
                Timeout=90,
                MemorySize=256,
                Environment={"Variables": env or {}},
                Publish=True,
            )
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
            return resp
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(3)
                continue
            raise
    raise last_err


def _wait_function_active(ctx, function_name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = lam.get_function_configuration(FunctionName=function_name)
        if resp["State"] == "Active":
            return
        if resp["State"] == "Failed":
            raise AssertionError(f"function failed to activate: {resp.get('StateReasonCode')}")
        time.sleep(2)
    raise AssertionError("function did not become Active in time")


def _invoke_lambda_cli(ctx, function_name: str, payload: dict[str, Any]):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        out_path = f.name
    # `fileb://` loads raw bytes from disk and lets the CLI handle any base64 encoding
    # itself — this works unmodified on both CLI v1 and v2, unlike passing the JSON
    # directly on the command line (which needs --cli-binary-format, a v2-only flag).
    in_path = out_path + ".in"
    with open(in_path, "w") as f:
        f.write(json.dumps(payload))
    try:
        meta = _run_aws(
            ctx,
            "lambda",
            "invoke",
            "--function-name",
            function_name,
            "--payload",
            f"fileb://{in_path}",
            "--cli-read-timeout",
            "120",
            out_path,
            timeout_s=130.0,
        )
        with open(out_path) as f:
            body_text = f.read()
        try:
            body = json.loads(body_text) if body_text.strip() else {}
        except (json.JSONDecodeError, ValueError):
            body = body_text
        return meta, body
    finally:
        os.unlink(out_path)
        os.unlink(in_path)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
