"""cli-lambda-sesv2-describe-email-identity."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import zipfile
import io

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-sesv2-describe-email-identity"
GROUP = "cli-sdk-interop"
SERVICES = ["lambda", "sesv2"]

_HANDLER_CODE = """
import json
import boto3

def handler(event, context):
    client = boto3.client("sesv2")
    identity = event["identity"]
    client.create_email_identity(
        EmailIdentity=identity,
        Tags=[{"Key": "created-by", "Value": "lambda"}],
    )
    info = client.get_email_identity(EmailIdentity=identity)
    result = {
        "identityType": info["IdentityType"],
        "tags": info.get("Tags", []),
    }
    print("SESV2_RESULT " + json.dumps(result))
    return result
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A domain identity created by a Lambda via boto3 is described by both `aws sesv2
    get-email-identity` and boto3 get_email_identity with the IdentityType/Tags the function
    observed at creation.
    """
    require_tools("aws")

    role_name = ctx.unique_name("sim2real-sesv2-role-")
    role_arn = _create_lambda_role_cli(ctx, role_name, {"sesv2-identity": _sesv2_identity_policy()})

    function_name = ctx.unique_name("sim2real-sesv2-fn-")
    zip_path = _write_zip(_HANDLER_CODE)
    try:
        _create_function_with_retry(ctx, function_name, role_arn, zip_path)
    finally:
        os.unlink(zip_path)
    _run_aws(
        ctx, "lambda", "wait", "function-active", "--function-name", function_name, timeout_s=180.0
    )

    identity = ctx.unique_name("sim2real-sesv2-id-") + ".example.com"
    ses = ctx.client("sesv2")
    ctx.on_cleanup(lambda: ses.delete_email_identity(EmailIdentity=identity))

    result = _invoke_sync(ctx, function_name, {"identity": identity})
    assert result["meta"].get("FunctionError") is None, (
        f"expected no FunctionError, got invocation result {result}"
    )
    body = result["body"]
    assert body["identityType"] == "DOMAIN", (
        f"expected the function's own view to report IdentityType=DOMAIN, got {body['identityType']!r}"
    )

    cli_view = _run_aws(ctx, "sesv2", "get-email-identity", "--email-identity", identity)
    sdk_view = ses.get_email_identity(EmailIdentity=identity)

    assert cli_view["IdentityType"] == "DOMAIN", (
        f"expected CLI get-email-identity IdentityType=DOMAIN, got {cli_view['IdentityType']!r}"
    )
    assert sdk_view["IdentityType"] == "DOMAIN", (
        f"expected SDK get_email_identity IdentityType=DOMAIN, got {sdk_view['IdentityType']!r}"
    )
    assert cli_view["IdentityType"] == sdk_view["IdentityType"] == body["identityType"], (
        f"expected CLI, SDK and the function's own view to agree on IdentityType, got "
        f"cli={cli_view['IdentityType']!r} sdk={sdk_view['IdentityType']!r} body={body['identityType']!r}"
    )

    cli_tags = {t["Key"]: t["Value"] for t in cli_view.get("Tags", [])}
    sdk_tags = {t["Key"]: t["Value"] for t in sdk_view.get("Tags", [])}
    body_tags = {t["Key"]: t["Value"] for t in body.get("tags", [])}
    assert cli_tags.get("created-by") == "lambda", (
        f"expected CLI view to show tag created-by=lambda, got tags {cli_tags}"
    )
    assert cli_tags == sdk_tags == body_tags, (
        f"expected CLI, SDK and the function's own view of tags to agree, got "
        f"cli={cli_tags} sdk={sdk_tags} body={body_tags}"
    )



def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command with the check's AWS creds and region in the env."""
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
    """Run an AWS CLI command; return parsed JSON (dict/list) or raw stdout string."""
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", "--no-cli-pager", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _write_zip(handler_code: str) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    fd, path = tempfile.mkstemp(suffix=".zip")
    with os.fdopen(fd, "wb") as f:
        f.write(buf.getvalue())
    return path


def _sesv2_identity_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ses:CreateEmailIdentity",
                    "ses:GetEmailIdentity",
                    "ses:TagResource",
                ],
                "Resource": "*",
            }
        ],
    }


def _create_lambda_role_cli(ctx, role_name: str, inline_policies: dict) -> str:
    """Creates an IAM role trusted by lambda.amazonaws.com plus basic logging and the
    given extra inline policies (name -> policy document). Registers cleanup. Returns
    the role ARN."""
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
    resp = _run_aws(
        ctx,
        "iam",
        "create-role",
        "--role-name",
        role_name,
        "--assume-role-policy-document",
        json.dumps(trust),
        "--tags",
        f"Key=sim2real,Value={CHECK}",
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup():
        iam = ctx.client("iam")
        try:
            names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            return
        for name in names:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    logging_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            }
        ],
    }
    _run_aws(
        ctx,
        "iam",
        "put-role-policy",
        "--role-name",
        role_name,
        "--policy-name",
        "basic-logging",
        "--policy-document",
        json.dumps(logging_policy),
    )
    for name, doc in inline_policies.items():
        _run_aws(
            ctx,
            "iam",
            "put-role-policy",
            "--role-name",
            role_name,
            "--policy-name",
            name,
            "--policy-document",
            json.dumps(doc),
        )
    return role_arn


def _safe_delete_function(ctx, function_name: str) -> None:
    try:
        ctx.client("lambda").delete_function(FunctionName=function_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_function_with_retry(ctx, function_name: str, role_arn: str, zip_path: str, timeout_s=90.0):
    """create-function via CLI, retrying while the freshly-created role has not yet
    propagated (IAM eventual consistency). Registers cleanup on success."""
    args = [
        "aws", "--output", "json", "--no-cli-pager", "lambda", "create-function",
        "--function-name", function_name,
        "--runtime", "python3.12",
        "--role", role_arn,
        "--handler", "index.handler",
        "--timeout", "30",
        "--zip-file", f"fileb://{zip_path}",
        "--tags", f"sim2real={CHECK}",
    ]
    deadline = time.monotonic() + timeout_s
    while True:
        proc = _run_shell(ctx, args, timeout_s=30.0, check=False)
        if proc.returncode == 0:
            ctx.on_cleanup(lambda: _delete_function_log_group(ctx, function_name))
            ctx.on_cleanup(lambda: _safe_delete_function(ctx, function_name))
            return json.loads(proc.stdout)
        if "cannot be assumed by Lambda" not in proc.stderr or time.monotonic() >= deadline:
            raise AssertionError(f"create-function failed (rc={proc.returncode}): {proc.stderr[-500:]}")
        time.sleep(3)


def _invoke_sync(ctx, function_name: str, payload: dict) -> dict:
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        meta = _run_aws(
            ctx,
            "lambda",
            "invoke",
            "--function-name",
            function_name,
            "--cli-binary-format",
            "raw-in-base64-out",
            "--payload",
            json.dumps(payload),
            out_path,
        )
        with open(out_path) as f:
            body = json.load(f)
    finally:
        os.unlink(out_path)
    return {"meta": meta, "body": body}


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on first invocation; it must stay absent across two reads
    2 s apart because late log delivery can recreate it. A group still present after 30 s raises.
    """
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    absent = 0
    while True:
        if absent == 0:
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        time.sleep(2.0)
        absent = 0 if present() else absent + 1
        if absent == 2:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
