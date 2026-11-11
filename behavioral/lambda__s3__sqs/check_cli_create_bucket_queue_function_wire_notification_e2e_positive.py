"""cli-create-bucket-queue-function-wire-notification-e2e-positive."""
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

CHECK = "cli-create-bucket-queue-function-wire-notification-e2e-positive"
GROUP = "delivery"
SERVICES = ["lambda", "s3", "sqs"]

_MANAGED_TAG_KEY = "sim2real:managed"

HANDLER_SRC = '''
import boto3, json, os

def handler(event, context):
    sqs = boto3.client("sqs")
    queue_url = os.environ["QUEUE_URL"]
    for rec in event.get("Records", []):
        s3info = rec["s3"]
        body = json.dumps({"bucket": s3info["bucket"]["name"], "key": s3info["object"]["key"]})
        sqs.send_message(QueueUrl=queue_url, MessageBody=body)
    return {"status": "ok"}
'''


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI-driven bucket+queue+function+notification wiring delivers a real message end to end."""
    require_tools("aws")

    bucket = ctx.unique_name("sim2real-e2e-bkt-")
    queue_name = ctx.unique_name("sim2real-e2e-q-")
    func_name = ctx.unique_name("sim2real-e2e-fn-")

    _create_bucket_cli(ctx, bucket)
    queue_url, queue_arn = _create_queue_cli(ctx, queue_name)

    role_arn = _create_lambda_role(
        ctx,
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
        },
    )
    func_arn = _create_function_cli(
        ctx, func_name, role_arn, HANDLER_SRC, env={"QUEUE_URL": queue_url}
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _run_aws(
        ctx,
        "lambda",
        "add-permission",
        "--function-name",
        func_name,
        "--statement-id",
        "sim2real-s3-invoke",
        "--action",
        "lambda:InvokeFunction",
        "--principal",
        "s3.amazonaws.com",
        "--source-arn",
        f"arn:aws:s3:::{bucket}",
        "--source-account",
        account_id,
    )

    notif_cfg = {
        "LambdaFunctionConfigurations": [
            {"LambdaFunctionArn": func_arn, "Events": ["s3:ObjectCreated:*"]}
        ]
    }
    _run_aws(
        ctx,
        "s3api",
        "put-bucket-notification-configuration",
        "--bucket",
        bucket,
        "--notification-configuration",
        json.dumps(notif_cfg),
    )

    key = "incoming/e2e-test-object.txt"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("hello-e2e")
        local_path = f.name
    try:
        _run_aws(ctx, "s3", "cp", local_path, f"s3://{bucket}/{key}")
    finally:
        os.unlink(local_path)

    sqs = ctx.client("sqs")
    deadline = time.monotonic() + 90.0
    found = None
    while time.monotonic() < deadline and found is None:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            if body.get("key") == key:
                found = body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if found is None:
        raise AssertionError("expected notification message never arrived in queue within 90s")
    assert found["bucket"] == bucket, f"expected bucket {bucket!r} in relayed message, got {found['bucket']!r}"
    assert found["key"] == key, f"expected key {key!r} in relayed message, got {found['key']!r}"


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
    if ctx.region != "us-east-1":
        args += ["--create-bucket-configuration", f"LocationConstraint={ctx.region}"]
    _run_aws(ctx, *args)
    ctx.client("s3").get_waiter("bucket_exists").wait(Bucket=name, WaiterConfig={"Delay": 2, "MaxAttempts": 50})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    _run_aws(
        ctx,
        "s3api",
        "put-bucket-tagging",
        "--bucket",
        name,
        "--tagging",
        json.dumps({"TagSet": [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]}),
    )


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


def _create_queue_cli(ctx, name):
    out = _run_aws(
        ctx, "sqs", "create-queue", "--queue-name", name, "--tags", json.dumps({_MANAGED_TAG_KEY: "true"})
    )
    url = out["QueueUrl"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "sqs", "delete-queue", "--queue-url", url, check=False))
    arn = _run_aws(ctx, "sqs", "get-queue-attributes", "--queue-url", url, "--attribute-names", "QueueArn")[
        "Attributes"
    ]["QueueArn"]
    return url, arn


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
        Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}],
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
            json.dumps({_MANAGED_TAG_KEY: "true"}),
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
