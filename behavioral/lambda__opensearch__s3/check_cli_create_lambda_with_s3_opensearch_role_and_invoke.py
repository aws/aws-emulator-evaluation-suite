"""cli-create-lambda-with-s3-opensearch-role-and-invoke."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-create-lambda-with-s3-opensearch-role-and-invoke"
GROUP = "cli-workflow"
SERVICES = ["lambda", "opensearch", "s3"]

_HANDLER_SRC = '''
import boto3
import os


def handler(event, context):
    s3 = boto3.client("s3")
    opensearch = boto3.client("opensearch")
    bucket = os.environ["TARGET_BUCKET"]
    key = os.environ.get("TARGET_KEY", "lambda-wrote-this.txt")
    s3.put_object(Bucket=bucket, Key=key, Body=b"hello-from-lambda")
    domains = opensearch.list_domain_names()
    return {
        "s3_put": "ok",
        "opensearch_domain_names": sorted(d["DomainName"] for d in domains.get("DomainNames", [])),
    }
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI creates a role with S3+OpenSearch policies, a Lambda function, invokes it, and
    confirms both the S3 write and the OpenSearch control-plane call the function performed
    actually took effect."""
    require_tools("aws")

    _account_id(ctx)
    bucket = _create_bucket(ctx)
    role_name = ctx.unique_name("sim2real-role-")
    statements = [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": f"arn:aws:s3:::{bucket}/*",
        },
        {
            "Effect": "Allow",
            "Action": ["es:ListDomainNames"],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        },
    ]
    role_arn = _create_lambda_role(ctx, role_name, statements)

    function_name = ctx.unique_name("sim2real-fn-")
    zip_path = _make_lambda_zip(_HANDLER_SRC)
    _create_lambda_function_cli(
        ctx,
        function_name,
        role_arn,
        zip_path,
        env={"TARGET_BUCKET": bucket, "TARGET_KEY": "lambda-wrote-this.txt"},
    )
    _wait_for_function_active(ctx, function_name)

    meta, payload = _invoke_lambda_cli(ctx, function_name, {})
    assert meta.get("StatusCode") == 200, f"expected StatusCode 200, got {meta.get('StatusCode')!r}"
    assert "FunctionError" not in meta, f"unexpected FunctionError: {payload}"
    assert payload["s3_put"] == "ok", f"expected s3_put == 'ok', got {payload.get('s3_put')!r}"

    # The role's es:ListDomainNames grant let the function's call succeed; the account's domain
    # inventory is not the check's, so only the answer's shape is asserted.
    names = payload["opensearch_domain_names"]
    assert isinstance(names, list) and all(isinstance(n, str) for n in names), (
        f"expected the function's ListDomainNames call to return a list of domain names, got {names!r}"
    )

    s3 = ctx.client("s3")
    body = s3.get_object(Bucket=bucket, Key="lambda-wrote-this.txt")["Body"].read()
    assert body == b"hello-from-lambda", f"expected b'hello-from-lambda', got {body!r}"


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with the run's AWS creds + region in the
    env (via ctx.subprocess_env). Raises on non-zero exit when check=True. Returns CompletedProcess."""
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
    """Run a multi-line bash script (set -euo pipefail) with the run's AWS creds configured."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(
            ctx,
            ["bash", script_path],
            timeout_s=timeout_s,
            check=check,
            env_extra=env_extra,
        )
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    """Run an AWS CLI command; return parsed JSON (dict/list) or raw stdout string."""
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


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _create_lambda_role(ctx, role_name: str, policy_statements: list) -> str:
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    _run_aws(
        ctx,
        "iam",
        "create-role",
        "--role-name",
        role_name,
        "--assume-role-policy-document",
        trust_policy,
        "--tags",
        "Key=sim2real,Value=" + CHECK,
    )
    ctx.on_cleanup(
        lambda: _run_shell(ctx, ["aws", "iam", "delete-role", "--role-name", role_name], check=False)
    )
    policy_name = f"{role_name}-inline"
    _run_aws(
        ctx,
        "iam",
        "put-role-policy",
        "--role-name",
        role_name,
        "--policy-name",
        policy_name,
        "--policy-document",
        json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
    )
    ctx.on_cleanup(
        lambda: _run_shell(
            ctx,
            ["aws", "iam", "delete-role-policy", "--role-name", role_name, "--policy-name", policy_name],
            check=False,
        )
    )
    return f"arn:aws:iam::{_account_id(ctx)}:role/{role_name}"


def _make_lambda_zip(handler_source: str) -> str:
    tmp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(tmp_dir, "function.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_source)
    return zip_path


def _create_lambda_function_cli(
    ctx, function_name: str, role_arn: str, zip_path: str, *, handler="lambda_function.handler", env=None, timeout=30
):
    env_arg = []
    if env:
        env_arg = ["--environment", json.dumps({"Variables": env})]
    deadline = time.monotonic() + 90.0
    last_err = ""
    while time.monotonic() < deadline:
        proc = _run_shell(
            ctx,
            [
                "aws",
                "--output",
                "json",
                "lambda",

                "create-function",
                "--function-name",
                function_name,
                "--runtime",
                "python3.12",
                "--role",
                role_arn,
                "--handler",
                handler,
                "--zip-file",
                f"fileb://{zip_path}",
                "--timeout",
                str(timeout),
                "--tags",
                f"sim2real={CHECK}",
                *env_arg,
            ],
            check=False,
        )
        if proc.returncode == 0:
            ctx.on_cleanup(
                lambda: _run_shell(
                    ctx, ["aws", "lambda", "delete-function", "--function-name", function_name], check=False
                )
            )
            return json.loads(proc.stdout)
        last_err = proc.stderr
        if "InvalidParameterValueException" in proc.stderr or "cannot be assumed" in proc.stderr:
            time.sleep(5)
            continue
        raise AssertionError(f"create-function failed: {proc.stderr[-500:]}")
    raise AssertionError(f"create-function did not succeed after role propagation wait: {last_err[-500:]}")


def _wait_for_function_active(ctx, function_name: str, timeout_s=90.0, interval_s=3.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus", "Successful") == "Successful":
            return cfg
        time.sleep(interval_s)
    raise AssertionError(f"function {function_name} did not become Active within {timeout_s}s")


def _cli_major_version(ctx) -> int:
    """Detect installed AWS CLI major version (1 or 2) so callers can gate v2-only flags
    like --cli-binary-format (unsupported on v1)."""
    proc = _run_shell(ctx, ["aws", "--version"], check=False)
    text = proc.stdout + proc.stderr
    if "aws-cli/2" in text:
        return 2
    return 1


def _invoke_lambda_cli(ctx, function_name: str, payload: dict):
    out_dir = tempfile.mkdtemp()
    out_path = os.path.join(out_dir, "out.json")
    payload_path = os.path.join(out_dir, "payload.json")
    with open(payload_path, "w") as f:
        json.dump(payload, f)
    cmd = [
        "aws",
        "--output",
        "json",
        "lambda",
        "invoke",
        "--function-name",
        function_name,
    ]
    if _cli_major_version(ctx) >= 2:
        cmd += ["--cli-binary-format", "raw-in-base64-out"]
    cmd += ["--payload", f"file://{payload_path}", out_path]
    proc = _run_shell(ctx, cmd, check=True)
    meta = json.loads(proc.stdout) if proc.stdout.strip() else {}
    with open(out_path) as f:
        response_payload = json.load(f)
    return meta, response_payload


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
