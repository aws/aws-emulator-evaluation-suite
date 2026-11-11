"""cli-opensearchserverless-collection-missing-permission-negative."""
from __future__ import annotations

import io
import json
import os
import re
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-opensearchserverless-collection-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["bedrock-agent", "lambda", "opensearchserverless"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role policy omits aoss:ListCollections gets AccessDeniedException and no collection list,
    while an identical Lambda whose role grants it gets a collection list: the missing action alone is denied."""
    require_tools("aws")

    code = (
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    client = boto3.client('opensearchserverless')\n"
        "    resp = client.list_collections()\n"
        "    names = [c['name'] for c in resp.get('collectionSummaries', [])]\n"
        "    return {'collections': names}\n"
    )

    # --- negative: role's CLI-attached policy lacks aoss:ListCollections ---
    neg_role_arn, neg_role_name = _create_lambda_role_base(ctx)
    _put_role_policy_cli(
        ctx,
        neg_role_name,
        "logs-only",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "*",
                }
            ],
        },
    )
    neg_function = ctx.unique_name("sim2real-oss-list-deny-")
    _create_function_with_retry(ctx, neg_function, neg_role_arn, _lambda_zip_bytes(code))
    _wait_function_active(ctx, neg_function)

    # --- positive control: identical setup, but the CLI-attached policy includes it ---
    pos_role_arn, pos_role_name = _create_lambda_role_base(ctx)
    _put_role_policy_cli(
        ctx,
        pos_role_name,
        "logs-and-aoss",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "*",
                },
                {"Effect": "Allow", "Action": "aoss:ListCollections", "Resource": "*"},
            ],
        },
    )
    pos_function = ctx.unique_name("sim2real-oss-list-allow-")
    _create_function_with_retry(ctx, pos_function, pos_role_arn, _lambda_zip_bytes(code))
    _wait_function_active(ctx, pos_function)

    # negative: invoke returns an unhandled AccessDeniedException, no collection list
    neg_meta, neg_body = _invoke_lambda_cli(ctx, neg_function, {})
    assert neg_meta.get("FunctionError") == "Unhandled", f"expected an unhandled error, got: {neg_meta}"
    code_str = _extract_boto_error_code(neg_body.get("errorMessage", ""))
    assert code_str == "AccessDeniedException", f"expected AccessDeniedException, got {code_str} ({neg_body})"
    assert "collections" not in neg_body, f"collections leaked despite denied permission: {neg_body}"

    # positive control: identical call succeeds and returns a collection list
    pos_meta, pos_body = _invoke_lambda_cli(ctx, pos_function, {})
    assert "FunctionError" not in pos_meta, f"unexpected function error: {pos_body}"
    assert isinstance(pos_body.get("collections"), list), f"expected a collections list, got {pos_body}"


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
            f"  stdout: {result.stdout[-1500:]}\n"
            f"  stderr: {result.stderr[-1500:]}"
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


def _create_lambda_role_base(ctx) -> tuple[str, str]:
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn, role_name


def _put_role_policy_cli(ctx, role_name: str, policy_name: str, policy_document: dict):
    iam = ctx.client("iam")
    full_policy_name = f"{role_name}-{policy_name}"
    _run_aws(
        ctx,
        "iam",
        "put-role-policy",
        "--role-name",
        role_name,
        "--policy-name",
        full_policy_name,
        "--policy-document",
        json.dumps(policy_document),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=full_policy_name))


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
                Timeout=60,
                MemorySize=256,
                Environment={"Variables": env or {}},
                Publish=True,
                Tags={"sim2real": CHECK},
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
            out_path,
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


def _extract_boto_error_code(error_message: str) -> str | None:
    m = re.search(r"An error occurred \((\w+)\)", error_message or "")
    return m.group(1) if m else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
