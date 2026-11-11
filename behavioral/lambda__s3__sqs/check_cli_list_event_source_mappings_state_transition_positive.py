"""cli-list-event-source-mappings-state-transition-positive."""
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

CHECK = "cli-list-event-source-mappings-state-transition-positive"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "s3", "sqs"]

HANDLER_SRC = '''
def handler(event, context):
    return {"records": len(event.get("Records", []))}
'''


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created ESM starts Creating and `list-event-source-mappings` reflects it reaching Enabled."""
    require_tools("aws")

    queue_name = ctx.unique_name("sim2real-esmst-q-")
    func_name = ctx.unique_name("sim2real-esmst-fn-")

    _, queue_arn = _create_queue_cli(ctx, queue_name)
    role_arn = _create_lambda_role(
        ctx,
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                    "Resource": queue_arn,
                }
            ],
        },
    )
    _create_function_cli(ctx, func_name, role_arn, HANDLER_SRC)

    # IAM role permissions can take a few seconds to propagate; CreateEventSourceMapping
    # validates sqs:ReceiveMessage against the role immediately, so retry on that specific error.
    create_args = [
        "aws", "--output", "json", "lambda", "create-event-source-mapping",
        "--event-source-arn", queue_arn,
        "--function-name", func_name,
        "--batch-size", "1",
        "--tags", "sim2real:managed=true",
    ]
    deadline = time.monotonic() + 30.0
    while True:
        proc = _run_shell(ctx, create_args, timeout_s=30.0, check=False)
        if proc.returncode == 0:
            break
        if "execution role does not have permissions" not in proc.stderr or time.monotonic() >= deadline:
            raise AssertionError(f"create-event-source-mapping failed (rc={proc.returncode}): {proc.stderr[-500:]}")
        time.sleep(3)
    create_out = json.loads(proc.stdout)
    uuid_ = create_out["UUID"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "lambda", "delete-event-source-mapping", "--uuid", uuid_, check=False))

    initial_state = create_out["State"]
    assert initial_state == "Creating", f"expected freshly created ESM to report State=Creating, got {initial_state}"

    final_state = None
    deadline = time.monotonic() + 120.0
    seen_states = [initial_state]
    while time.monotonic() < deadline:
        listed = _run_aws(
            ctx, "lambda", "list-event-source-mappings", "--event-source-arn", queue_arn, "--function-name", func_name
        )
        mapping = next(m for m in listed["EventSourceMappings"] if m["UUID"] == uuid_)
        seen_states.append(mapping["State"])
        if mapping["State"] == "Enabled":
            final_state = mapping["State"]
            break
        time.sleep(3)

    assert final_state == "Enabled", f"ESM never reached Enabled via list-event-source-mappings; saw {seen_states}"


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


def _create_queue_cli(ctx, name):
    out = _run_aws(ctx, "sqs", "create-queue", "--queue-name", name, "--tags", "sim2real:managed=true")
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
            "--tags",
            "sim2real:managed=true",
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
