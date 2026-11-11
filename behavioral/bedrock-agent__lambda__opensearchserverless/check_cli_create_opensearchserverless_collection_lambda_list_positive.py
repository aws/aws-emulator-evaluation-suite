"""cli-create-opensearchserverless-collection-lambda-list-positive."""

from __future__ import annotations

import io
import json
import os
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-create-opensearchserverless-collection-lambda-list-positive"
GROUP = "cli-roundtrip"
SERVICES = ["bedrock-agent", "lambda", "opensearchserverless"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CLI-created OpenSearch Serverless collection is visible to a Lambda function
    that lists collections via boto3, proving the control-plane write is durably
    observable cross-service (not just echoed back to the CLI caller)."""
    require_tools("aws")

    aoss = ctx.client("opensearchserverless")

    collection_name = (
        ctx.unique_name("sim2real-oss-").lower().replace("_", "-")[:32].rstrip("-")
    )
    policy_name = (
        ctx.unique_name("sim2real-ossenc-").lower().replace("_", "-")[:32].rstrip("-")
    )

    # --- Lambda that lists OpenSearch Serverless collections via boto3 ---
    role_arn = _create_lambda_role(
        ctx,
        extra_statements=[
            {"Effect": "Allow", "Action": "aoss:ListCollections", "Resource": "*"}
        ],
    )
    function_name = ctx.unique_name("sim2real-oss-list-")
    code = (
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    client = boto3.client('opensearchserverless')\n"
        "    resp = client.list_collections()\n"
        "    names = [c['name'] for c in resp.get('collectionSummaries', [])]\n"
        "    return {'collections': names}\n"
    )
    _create_function_with_retry(ctx, function_name, role_arn, _lambda_zip_bytes(code))
    _wait_function_active(ctx, function_name)

    # --- create the required encryption policy, then the collection, via the CLI ---
    enc_policy = {
        "Rules": [
            {
                "ResourceType": "collection",
                "Resource": [f"collection/{collection_name}"],
            }
        ],
        "AWSOwnedKey": True,
    }
    _run_aws(
        ctx,
        "opensearchserverless",
        "create-security-policy",
        "--name",
        policy_name,
        "--type",
        "encryption",
        "--policy",
        json.dumps(enc_policy),
    )

    def _cleanup_policy():
        try:
            aoss.delete_security_policy(name=policy_name, type="encryption")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_policy)

    _run_aws(
        ctx,
        "opensearchserverless",
        "create-collection",
        "--name",
        collection_name,
        "--type",
        "SEARCH",
        "--tags",
        json.dumps([{"key": "sim2real:managed", "value": "true"}]),
    )

    def _cleanup_collection():
        _poll_until(
            lambda: _collection_status(aoss, collection_name),
            lambda status: status in ("ACTIVE", "FAILED", None),
            timeout_s=240.0,
            interval_s=5.0,
        )
        try:
            aoss.delete_collection(name=collection_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_collection)

    # --- invoke the Lambda via the CLI and assert the CLI-created collection is visible ---
    meta, body = _invoke_lambda_cli(ctx, function_name, {})
    assert "FunctionError" not in meta, f"unexpected function error: {body}"
    assert collection_name in body.get("collections", []), (
        f"collection {collection_name!r} not visible via Lambda's boto3 ListCollections call: {body}"
    )


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


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _collection_status(aoss, name: str):
    resp = aoss.batch_get_collection(names=[name])
    details = resp.get("collectionDetails", [])
    if details:
        return details[0]["status"]
    if resp.get("collectionErrorDetails"):
        return None
    return None


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
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
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_function_with_retry(
    ctx,
    function_name,
    role_arn,
    code_bytes,
    handler="index.handler",
    env=None,
    timeout_s=90.0,
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
                Tags={"sim2real:managed": "true"},
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
            raise AssertionError(
                f"function failed to activate: {resp.get('StateReasonCode')}"
            )
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
