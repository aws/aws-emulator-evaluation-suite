"""cli-lambda-sesv2-describe-function-config."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-sesv2-describe-function-config"
GROUP = "sdk-cli-interop"
SERVICES = ["lambda", "sesv2"]

_HANDLER_CODE = """
import json
import boto3

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        resp = client.get_account()
        result = {"ok": True, "sendingEnabled": resp.get("SendingEnabled")}
    except Exception as e:
        err = getattr(e, "response", {}).get("Error", {})
        result = {"ok": False, "errorCode": err.get("Code"), "errorMessage": str(e)}
    print("SESV2_RESULT " + json.dumps(result))
    return result
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:representation",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """get-function-configuration reports the CLI-created role ARN and function name, and the
    function's sesv2 GetAccount call under that role returns the SendingEnabled a direct
    get-account returns."""
    require_tools("aws")

    role_name = ctx.unique_name("sim2real-interop-role-")
    func_name = ctx.unique_name("sim2real-interop-fn-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    perm_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "ses:GetAccount", "Resource": "*"}],
    }

    role_arn = _create_role(ctx, role_name, trust_policy, perm_policy)

    zip_path = _write_lambda_zip(_HANDLER_CODE)
    try:
        _create_function_with_retry(ctx, func_name, role_arn, zip_path)
        ctx.on_cleanup(lambda: _delete_function_log_group(ctx, func_name))
        ctx.on_cleanup(lambda: _run_aws(ctx, "lambda", "delete-function", "--function-name", func_name, check=False))
        _wait_function_active(ctx, func_name)

        cfg = _run_aws(ctx, "lambda", "get-function-configuration", "--function-name", func_name)
        role_from_iam = _run_aws(ctx, "iam", "get-role", "--role-name", role_name)

        body = _invoke_until_ok(ctx, func_name, {})
        direct = _run_aws(ctx, "sesv2", "get-account")
    finally:
        os.unlink(zip_path)

    assert cfg["Role"] == role_arn, f"lambda config role {cfg['Role']} != created role {role_arn}"
    assert role_from_iam["Role"]["Arn"] == role_arn, "iam get-role ARN diverges from create-role ARN"
    assert cfg["FunctionName"] == func_name

    assert body["ok"] is True, f"lambda-invoked sesv2.get_account did not succeed: {body}"
    assert body["sendingEnabled"] == direct["SendingEnabled"], (
        f"sending-enabled seen inside the function ({body['sendingEnabled']}) diverges from "
        f"an independent `aws sesv2 get-account` ({direct['SendingEnabled']})"
    )


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
    proc = _run_shell(ctx, ["aws", "--output", "json", "--no-cli-pager", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _write_lambda_zip(code: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return path


def _create_role(ctx, role_name, trust_policy, perm_policy) -> str:
    fd1, trust_path = tempfile.mkstemp(suffix=".json")
    fd2, perm_path = tempfile.mkstemp(suffix=".json")
    try:
        with open(trust_path, "w") as f:
            json.dump(trust_policy, f)
        with open(perm_path, "w") as f:
            json.dump(perm_policy, f)
        os.close(fd1)
        os.close(fd2)
        created = _run_aws(
            ctx, "iam", "create-role", "--role-name", role_name,
            "--assume-role-policy-document", f"file://{trust_path}",
        )
        role_arn = created["Role"]["Arn"]
        ctx.on_cleanup(lambda: _run_aws(ctx, "iam", "delete-role", "--role-name", role_name, check=False))
        _run_aws(
            ctx, "iam", "put-role-policy", "--role-name", role_name,
            "--policy-name", "sim2real-ses-policy",
            "--policy-document", f"file://{perm_path}",
        )
        ctx.on_cleanup(
            lambda: _run_aws(
                ctx, "iam", "delete-role-policy", "--role-name", role_name,
                "--policy-name", "sim2real-ses-policy", check=False,
            )
        )
        return role_arn
    finally:
        os.unlink(trust_path)
        os.unlink(perm_path)


def _create_function_with_retry(ctx, func_name, role_arn, zip_path, runtime="python3.12", timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        proc = _run_shell(
            ctx,
            [
                "aws", "--output", "json", "--no-cli-pager", "lambda", "create-function",
                "--function-name", func_name,
                "--runtime", runtime,
                "--role", role_arn,
                "--handler", "lambda_function.handler",
                "--zip-file", f"fileb://{zip_path}",
                "--timeout", "20",
            ],
            check=False,
        )
        if proc.returncode == 0:
            return json.loads(proc.stdout)
        last_err = proc.stderr
        if "InvalidParameterValueException" in proc.stderr or "cannot be assumed" in proc.stderr:
            time.sleep(5)
            continue
        raise AssertionError(f"lambda create-function failed: {proc.stderr[-500:]}")
    raise AssertionError(f"lambda create-function never succeeded (role propagation?): {last_err}")


def _wait_function_active(ctx, func_name, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = _run_aws(ctx, "lambda", "get-function-configuration", "--function-name", func_name)
        if cfg.get("State") == "Active":
            return cfg
        if cfg.get("State") == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg}")
        time.sleep(interval_s)
    raise AssertionError(f"function {func_name} never became Active within {timeout_s}s")


def _invoke_until_ok(ctx, func_name, payload: dict, timeout_s=90.0, interval_s=3.0) -> dict:
    fd, payload_path = tempfile.mkstemp(suffix=".json")
    fd2, out_path = tempfile.mkstemp(suffix=".json")
    try:
        with open(payload_path, "w") as f:
            json.dump(payload, f)
        os.close(fd)
        os.close(fd2)
        deadline = time.monotonic() + timeout_s
        last_body = None
        while time.monotonic() < deadline:
            meta = _run_aws(
                ctx, "lambda", "invoke",
                "--function-name", func_name,
                "--payload", f"file://{payload_path}",
                "--cli-binary-format", "raw-in-base64-out",
                out_path,
            )
            with open(out_path) as f:
                last_body = json.load(f)
            if meta.get("FunctionError") is None and last_body.get("ok") is True:
                return last_body
            time.sleep(interval_s)
        raise AssertionError(f"invocation never reported ok=True within {timeout_s}s; last body: {last_body}")
    finally:
        os.unlink(payload_path)
        os.unlink(out_path)


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across two reads 5 s apart. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not present():
            time.sleep(5.0)
            if not present():
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
