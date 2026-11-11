"""cli-put-bucket-notification-missing-permission-negative."""
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

CHECK = "cli-put-bucket-notification-missing-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]

HANDLER_SRC = '''
import boto3, json, os

def handler(event, context):
    s3 = boto3.client("s3")
    out_bucket = os.environ["OUT_BUCKET"]
    for rec in event.get("Records", []):
        key = rec["s3"]["object"]["key"]
        s3.put_object(Bucket=out_bucket, Key="processed/" + key, Body=b"done")
    return {"status": "ok"}
'''


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration targeting a Lambda without the s3.amazonaws.com invoke
    permission fails with InvalidArgument (exact message); after the grant, the same call and an
    upload-triggered invocation succeed."""
    require_tools("aws")

    bucket = ctx.unique_name("sim2real-noperm-bkt-")
    func_name = ctx.unique_name("sim2real-noperm-fn-")

    _create_bucket_cli(ctx, bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    role_arn = _create_lambda_role(
        ctx,
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"{bucket_arn}/*"}],
        },
    )
    func_arn = _create_function_cli(ctx, func_name, role_arn, HANDLER_SRC, env={"OUT_BUCKET": bucket})

    notif_cfg = {"LambdaFunctionConfigurations": [{"LambdaFunctionArn": func_arn, "Events": ["s3:ObjectCreated:*"]}]}
    # S3 validates that it can invoke the Lambda target at PUT time by test-invoking it; without
    # a resource policy granting s3.amazonaws.com lambda:InvokeFunction, the PUT itself is rejected.
    put_proc = _run_shell(
        ctx,
        [
            "aws", "--output", "json", "s3api", "put-bucket-notification-configuration",
            "--bucket", bucket,
            "--notification-configuration", json.dumps(notif_cfg),
        ],
        check=False,
    )
    code, message = _cli_error(put_proc, "PutBucketNotificationConfiguration")
    assert code == "InvalidArgument", (
        f"expected InvalidArgument for a Lambda target lacking the s3.amazonaws.com invoke permission, got {code!r}"
    )
    assert message == "Unable to validate the following destination configurations", (
        f"unexpected InvalidArgument message: {message!r}"
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
        bucket_arn,
        "--source-account",
        account_id,
    )

    # Now that the permission exists, the same PUT should succeed (positive control),
    # and an upload should actually invoke the function end-to-end.
    _run_aws(
        ctx,
        "s3api",
        "put-bucket-notification-configuration",
        "--bucket",
        bucket,
        "--notification-configuration",
        json.dumps(notif_cfg),
    )

    s3 = ctx.client("s3")
    key2 = "phase2/with-permission.txt"
    _put_text_object(s3, bucket, key2, "with-permission-upload")
    marker2 = "processed/" + key2
    deadline = time.monotonic() + 90.0
    positive_control_ok = False
    while time.monotonic() < deadline:
        try:
            s3.head_object(Bucket=bucket, Key=marker2)
            positive_control_ok = True
            break
        except Exception:
            time.sleep(3)
    assert positive_control_ok, "positive control failed: function was never invoked even after granting permission"


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


def _cli_error(proc, operation):
    """The (code, message) of the aws CLI error for ``operation``; raises if the call succeeded."""
    if proc.returncode == 0:
        raise AssertionError(f"{operation} was expected to fail but succeeded: {proc.stdout[-500:]!r}")
    prefix = "An error occurred ("
    for line in proc.stderr.splitlines():
        idx = line.find(prefix)
        if idx != -1 and f"when calling the {operation} operation: " in line:
            code = line[idx + len(prefix):line.index(")", idx)]
            return code, line.split(f"when calling the {operation} operation: ", 1)[1]
    raise AssertionError(f"{operation} failed without an AWS error line: {proc.stderr[-500:]!r}")


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _put_text_object(s3, bucket, key, content):
    s3.put_object(Bucket=bucket, Key=key, Body=content.encode())


def _create_bucket_cli(ctx, name):
    args = ["s3api", "create-bucket", "--bucket", name, "--region", ctx.region]
    if ctx.region != "us-east-1":
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for — the
        # literal is a real API quirk of that region, not a hardcoded target region.
        args += ["--create-bucket-configuration", f"LocationConstraint={ctx.region}"]
    _run_aws(ctx, *args)
    ctx.client("s3").get_waiter("bucket_exists").wait(Bucket=name, WaiterConfig={"Delay": 2, "MaxAttempts": 50})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    ctx.client("s3").put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        ]
        if env:
            args += ["--environment", json.dumps({"Variables": env})]
        args += ["--tags", "sim2real:managed=true"]
        # A fresh role takes seconds to become assumable by Lambda and a valid KMS grantee for the
        # environment-variable key; retry only those two propagation refusals.
        deadline = time.monotonic() + min(90.0, ctx.time_left() or 90.0)
        while True:
            proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=30.0, check=False)
            propagating = (
                "cannot be assumed by Lambda" in proc.stderr
                or "KMS key is invalid for CreateGrant" in proc.stderr
            )
            if proc.returncode == 0 or not propagating or time.monotonic() >= deadline:
                break
            time.sleep(2)
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
