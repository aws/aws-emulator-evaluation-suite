"""cli-invoke-lambda-manual-test-event-positive."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-invoke-lambda-manual-test-event-positive"
GROUP = "delivery"
SERVICES = ["lambda", "s3", "sqs"]

_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]

HANDLER_SRC = '''
import boto3, json, os

def handler(event, context):
    s3 = boto3.client("s3")
    out_bucket = os.environ["OUT_BUCKET"]
    processed = []
    for rec in event.get("Records", []):
        key = rec["s3"]["object"]["key"]
        src_bucket = rec["s3"]["bucket"]["name"]
        marker_key = "processed/" + key
        body = json.dumps({"source_bucket": src_bucket, "source_key": key}).encode()
        s3.put_object(Bucket=out_bucket, Key=marker_key, Body=body)
        processed.append(marker_key)
    return {"processed": processed}
'''


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws lambda invoke` with a synthetic S3 event payload drives the function's real S3 write."""
    require_tools("aws")

    bucket = ctx.unique_name("sim2real-inv-bkt-")
    func_name = ctx.unique_name("sim2real-inv-fn-")

    _create_bucket_cli(ctx, bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    role_arn = _create_lambda_role(
        ctx,
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"{bucket_arn}/*"}],
        },
    )
    _create_function_cli(ctx, func_name, role_arn, HANDLER_SRC, env={"OUT_BUCKET": bucket})

    src_key = "incoming/testfile.txt"
    synthetic_event = {
        "Records": [
            {
                "eventVersion": "2.1",
                "eventSource": "aws:s3",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {"name": bucket, "arn": bucket_arn},
                    "object": {"key": src_key},
                },
            }
        ]
    }
    invoke_meta, invoke_payload = _invoke_lambda_cli(ctx, func_name, synthetic_event)
    assert invoke_meta.get("FunctionError") is None, (
        f"unexpected FunctionError: meta={invoke_meta} payload={invoke_payload}"
    )

    marker_key = "processed/" + src_key
    obj = ctx.client("s3").get_object(Bucket=bucket, Key=marker_key)
    body = json.loads(obj["Body"].read())
    assert body["source_bucket"] == bucket
    assert body["source_key"] == src_key


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["AWS_PAGER"] = ""
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


def _create_bucket_cli(ctx, name):
    args = ["s3api", "create-bucket", "--bucket", name, "--region", ctx.region]
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for; every other
    # region requires it. Not a region pin — ctx.region drives the bucket's actual region.
    if ctx.region != "us-east-1":
        args += ["--create-bucket-configuration", f"LocationConstraint={ctx.region}"]
    _run_aws(ctx, *args)
    s3 = ctx.client("s3")
    s3.get_waiter("bucket_exists").wait(Bucket=name, WaiterConfig={"Delay": 2, "MaxAttempts": 50})
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": _MANAGED_TAGS + [{"Key": "sim2real:prefix", "Value": "sim2real-inv-bkt"}]},
    )
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))


def _delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        for o in s3.list_objects_v2(Bucket=name).get("Contents", []):
            s3.delete_object(Bucket=name, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _make_zip_file(handler_src):
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("index.py", handler_src)
    return path


def _create_lambda_role(ctx, inline_policy=None, managed_arns=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=_MANAGED_TAGS + [{"Key": "sim2real:prefix", "Value": "sim2real-inv-role"}],
    )["Role"]
    role_arn = role["Arn"]

    def _cleanup_role():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        for arn in managed_arns or []:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        if inline_policy:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=f"{role_name}-inline")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    for arn in managed_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName=f"{role_name}-inline", PolicyDocument=json.dumps(inline_policy))
    return role_arn


def _wait_function_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} did not become Active in {timeout_s}s")


def _create_function_cli(ctx, name, role_arn, handler_src, env=None, timeout=30):
    zip_path = _make_zip_file(handler_src)
    try:
        args = [
            "lambda",
            "create-function",
            "--function-name",
            name,
            "--runtime",
            "python3.12",
            "--role",
            role_arn,
            "--handler",
            "index.handler",
            "--zip-file",
            f"fileb://{zip_path}",
            "--timeout",
            str(timeout),
            "--tags",
            "sim2real:managed=true,sim2real:prefix=sim2real-inv-fn",
        ]
        if env:
            args += ["--environment", json.dumps({"Variables": env})]
        # A fresh role takes seconds to become assumable by Lambda; retry only that refusal.
        for _ in range(10):
            proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=30.0, check=False)
            if proc.returncode == 0 or "cannot be assumed by Lambda" not in proc.stderr:
                break
            time.sleep(3)
        if proc.returncode != 0:
            raise AssertionError(f"create-function failed (rc={proc.returncode}): {proc.stderr[-500:]}")
        out = json.loads(proc.stdout)
    finally:
        os.unlink(zip_path)
    func_arn = out["FunctionArn"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "lambda", "delete-function", "--function-name", name, check=False))
    _wait_function_active(ctx, name)
    return func_arn


def _invoke_lambda_cli(ctx, func_name, payload):
    """Returns (invoke_metadata, response_payload). `aws lambda invoke` writes the function's
    return value to the output file but prints the invocation's own metadata — including
    FunctionError — to stdout; the two must not be conflated."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        payload_path = f.name
    out_fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(out_fd)
    try:
        proc = _run_shell(
            ctx,
            [
                "aws",
                "lambda",
                "invoke",
                "--function-name",
                func_name,
                "--payload",
                f"file://{payload_path}",
                "--cli-binary-format",
                "raw-in-base64-out",
                out_path,
            ],
            check=False,
        )
        if proc.returncode != 0:
            proc = _run_shell(
                ctx,
                ["aws", "lambda", "invoke", "--function-name", func_name, "--payload", f"file://{payload_path}", out_path],
                check=True,
            )
        stdout = proc.stdout.strip()
        invoke_meta = json.loads(stdout) if stdout else {}
        with open(out_path) as f:
            content = f.read().strip()
        response_payload = json.loads(content) if content else {}
        return invoke_meta, response_payload
    finally:
        os.unlink(payload_path)
        if os.path.exists(out_path):
            os.unlink(out_path)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
