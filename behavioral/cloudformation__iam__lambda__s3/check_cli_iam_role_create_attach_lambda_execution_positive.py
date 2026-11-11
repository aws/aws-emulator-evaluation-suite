"""cli-iam-role-create-attach-lambda-execution-positive."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import zipfile
from io import BytesIO

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-iam-role-create-attach-lambda-execution-positive"
GROUP = "cli-roundtrip"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An aws-cli create-role/put-role-policy/create-function/invoke chain results in the
    function successfully writing an object to S3 with the requested key/body."""
    require_tools("aws")

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cliiam-")
    _create_bucket(ctx, s3, bucket)

    role_name = ctx.unique_name("sim2real-cliiam-role-")
    function_name = ctx.unique_name("sim2real-cliiam-fn-")
    policy_name = "s3-write-inline"
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    exec_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"},
        ],
    }

    trust_path = _write_temp_json(trust_policy)
    policy_path = _write_temp_json(exec_policy)
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

        _run_aws(
            ctx, "iam", "attach-role-policy",
            "--role-name", role_name, "--policy-arn", managed_policy_arn,
        )
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "iam", "detach-role-policy", "--role-name", role_name,
                  "--policy-arn", managed_policy_arn], check=False,
        ))

        _run_aws(
            ctx, "iam", "put-role-policy",
            "--role-name", role_name,
            "--policy-name", policy_name,
            "--policy-document", f"file://{policy_path}",
        )
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "iam", "delete-role-policy", "--role-name", role_name,
                  "--policy-name", policy_name], check=False,
        ))
    finally:
        os.unlink(trust_path)
        os.unlink(policy_path)

    handler_code = (
        "import os\n"
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    s3 = boto3.client('s3')\n"
        "    s3.put_object(Bucket=os.environ['BUCKET_NAME'], Key=event['key'], Body=event['body'])\n"
        "    return {'wrote': event['key']}\n"
    )
    zip_path = _write_zip(handler_code)
    try:
        create_args = [
            "lambda", "create-function",
            "--function-name", function_name,
            "--runtime", "python3.12",
            "--role", role_arn,
            "--handler", "index.handler",
            "--zip-file", f"fileb://{zip_path}",
            "--timeout", "30",
            "--environment", f"Variables={{BUCKET_NAME={bucket}}}",
            "--tags", "sim2real:managed=true",
        ]
        _create_function_with_role_propagation_retry(ctx, create_args)
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "lambda", "delete-function", "--function-name", function_name], check=False,
        ))
    finally:
        os.unlink(zip_path)

    _poll_until(
        lambda: _run_aws(ctx, "lambda", "get-function-configuration",
                          "--function-name", function_name).get("State"),
        lambda state: state == "Active",
        timeout_s=60, interval_s=2,
    )

    key = "written-by-lambda.txt"
    body = "hello-from-lambda-invoke"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as pf:
        json.dump({"key": key, "body": body}, pf)
        payload_path = pf.name
    out_path = payload_path + ".out"
    try:
        _run_aws(
            ctx, "lambda", "invoke",
            "--function-name", function_name,
            "--cli-binary-format", "raw-in-base64-out",
            "--payload", f"file://{payload_path}",
            out_path,
        )
        with open(out_path) as f:
            invoke_result = json.load(f)
        assert invoke_result == {"wrote": key}, f"unexpected invoke result: {invoke_result}"
    finally:
        os.unlink(payload_path)
        if os.path.exists(out_path):
            os.unlink(out_path)

    obj = _poll_until(
        lambda: _try_get_object(s3, bucket, key),
        lambda o: o is not None,
        timeout_s=30, interval_s=2,
    )
    written = obj["Body"].read().decode()
    assert written == body, f"expected s3 object body {body!r}, got {written!r}"


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


def _write_zip(handler_source: str) -> str:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_source)
    fd, path = tempfile.mkstemp(suffix=".zip")
    with os.fdopen(fd, "wb") as f:
        f.write(buf.getvalue())
    return path


def _create_bucket(ctx, s3, bucket: str) -> None:
    # us-east-1 is S3's own default region: CreateBucket rejects an explicit
    # LocationConstraint there, so ctx.region drives which call shape is used.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _try_get_object(s3, bucket, key):
    from botocore.exceptions import ClientError
    try:
        return s3.get_object(Bucket=bucket, Key=key)
    except ClientError:
        return None


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
    """IAM role trust propagation to Lambda can lag by several seconds after create-role; retry
    create-function only on that specific, documented transient failure."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
