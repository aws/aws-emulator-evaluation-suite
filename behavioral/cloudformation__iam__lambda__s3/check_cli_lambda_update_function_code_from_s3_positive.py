"""cli-lambda-update-function-code-from-s3-positive."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import time
import zipfile
from io import BytesIO

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-update-function-code-from-s3-positive"
GROUP = "code-deployment"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws lambda update-function-code --s3-bucket/--s3-key updates the function: the resulting
    CodeSha256 matches the sha256 of the uploaded S3 object, and the function's behavior
    actually changes to run the new code."""
    require_tools("aws")

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-codeupd-")
    _create_bucket(ctx, s3, bucket)

    role_name = ctx.unique_name("sim2real-codeupd-role-")
    function_name = ctx.unique_name("sim2real-codeupd-fn-")
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    trust_path = _write_temp_json(trust_policy)
    try:
        role = _run_aws(
            ctx, "iam", "create-role",
            "--role-name", role_name,
            "--assume-role-policy-document", f"file://{trust_path}",
            "--tags", "Key=sim2real:managed,Value=true",
        )
        role_arn = role["Role"]["Arn"]
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "iam", "delete-role", "--role-name", role_name], check=False,
        ))
        _run_aws(ctx, "iam", "attach-role-policy", "--role-name", role_name, "--policy-arn", managed_policy_arn)
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "iam", "detach-role-policy", "--role-name", role_name,
                  "--policy-arn", managed_policy_arn], check=False,
        ))
    finally:
        os.unlink(trust_path)

    v1_zip = _make_zip("def handler(event, context):\n    return {'version': 1}\n")
    v1_path = _write_bytes_to_temp(v1_zip, ".zip")
    try:
        create_args = [
            "lambda", "create-function",
            "--function-name", function_name,
            "--runtime", "python3.12",
            "--role", role_arn,
            "--handler", "index.handler",
            "--zip-file", f"fileb://{v1_path}",
            "--timeout", "30",
            "--tags", "sim2real:managed=true",
        ]
        _create_function_with_role_propagation_retry(ctx, create_args)
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "lambda", "delete-function", "--function-name", function_name], check=False,
        ))
    finally:
        os.unlink(v1_path)

    _poll_until(
        lambda: _run_aws(ctx, "lambda", "get-function-configuration",
                          "--function-name", function_name).get("State"),
        lambda state: state == "Active",
        timeout_s=60, interval_s=2,
    )
    v1_result = _invoke(ctx, function_name)
    assert v1_result == {"version": 1}, f"expected v1 invoke result {{'version': 1}}, got {v1_result!r}"

    v2_zip = _make_zip("def handler(event, context):\n    return {'version': 2}\n")
    expected_sha256 = base64.b64encode(hashlib.sha256(v2_zip).digest()).decode()
    code_key = "code-v2.zip"
    s3.put_object(Bucket=bucket, Key=code_key, Body=v2_zip)

    _run_aws(
        ctx, "lambda", "update-function-code",
        "--function-name", function_name,
        "--s3-bucket", bucket, "--s3-key", code_key,
    )

    updated = _poll_until(
        lambda: _run_aws(ctx, "lambda", "get-function-configuration", "--function-name", function_name),
        lambda cfg: cfg.get("LastUpdateStatus") == "Successful",
        timeout_s=60, interval_s=2,
    )
    assert updated["CodeSha256"] == expected_sha256, (
        f"CodeSha256 {updated['CodeSha256']!r} does not match sha256 of the uploaded S3 object {expected_sha256!r}"
    )

    v2_result = _invoke(ctx, function_name)
    assert v2_result == {"version": 2}, "function still runs the old code after update-function-code"


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
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _write_temp_json(obj) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    return path


def _make_zip(handler_source: str) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_source)
    return buf.getvalue()


def _write_bytes_to_temp(data: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _create_bucket(ctx, s3, bucket: str) -> None:
    # us-east-1 literal: S3 CreateBucket rejects an explicit LocationConstraint for that
    # region specifically, so the branch is on the region-pin quirk, not a hardcoded target.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_function_with_role_propagation_retry(ctx, create_args, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_err = ""
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, ["aws", "--output", "json", *create_args], check=False)
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        last_err = proc.stderr
        if "InvalidParameterValueException" in proc.stderr and "assumed" in proc.stderr:
            time.sleep(interval_s)
            continue
        raise AssertionError(f"create-function failed: {last_err[-500:]}")
    raise AssertionError(f"create-function never succeeded after role propagation wait: {last_err[-500:]}")


def _invoke(ctx, function_name):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as pf:
        json.dump({}, pf)
        payload_path = pf.name
    out_path = payload_path + ".out"
    try:
        _run_aws(
            ctx, "lambda", "invoke",
            "--function-name", function_name,
            "--payload", f"file://{payload_path}",
            out_path,
        )
        with open(out_path) as f:
            return json.load(f)
    finally:
        os.unlink(payload_path)
        if os.path.exists(out_path):
            os.unlink(out_path)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
