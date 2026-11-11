"""cli-lambda-sesv2-deploy-and-send-email."""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-lambda-sesv2-deploy-and-send-email"
GROUP = "cli-roundtrip"
SERVICES = ["lambda", "sesv2"]

_HANDLER_CODE = """
import json
import boto3

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        resp = client.send_email(
            FromEmailAddress=event["from"],
            Destination={"ToAddresses": [event["to"]]},
            Content={
                "Simple": {
                    "Subject": {"Data": event["subject"]},
                    "Body": {"Text": {"Data": event["body"]}},
                }
            },
        )
        result = {"ok": True, "messageId": resp["MessageId"]}
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        result = {"ok": False, "errorCode": code, "errorMessage": str(e)}
    print("SESV2_RESULT " + json.dumps(result))
    return result
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "requires:dns-baseline")
def run(ctx) -> None:
    """CLI provisions an IAM role + Lambda function wired with ses:SendEmail, invokes
    the function via the CLI, and the handler's own boto3 call to sesv2.send_email
    succeeds end-to-end (real MessageId returned, no FunctionError)."""
    require_tools("aws")
    sender = _get_verified_sender(ctx)

    role_name = ctx.unique_name("sim2real-sesv2-role-")
    role_arn = _create_lambda_role_cli(
        ctx, role_name, {"sesv2-send": _sesv2_send_policy()}
    )

    function_name = ctx.unique_name("sim2real-sesv2-fn-")
    zip_path = _write_zip(_HANDLER_CODE)
    try:
        _create_function_with_retry(ctx, function_name, role_arn, zip_path)
    finally:
        os.unlink(zip_path)
    _run_aws(
        ctx,
        "lambda",
        "wait",
        "function-active",
        "--function-name",
        function_name,
        timeout_s=180.0,
    )

    payload = {
        "from": sender,
        "to": "success@simulator.amazonses.com",
        "subject": "sim2real cli-roundtrip test",
        "body": "hello from a CLI-deployed lambda calling sesv2.send_email",
    }
    body = _invoke_until_ok(ctx, function_name, payload, timeout_s=90.0)
    assert body["ok"] is True, f"send_email did not succeed: {body}"
    assert isinstance(body["messageId"], str) and len(body["messageId"]) > 0, (
        f"expected a non-empty string MessageId from sesv2.send_email, got: {body.get('messageId')!r}"
    )


# ===== helpers =====


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command with the check's AWS credentials and region in the env."""
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


def _sesv2_send_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ses:SendEmail", "Resource": "*"}
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
        "Key=sim2real,Value=true",
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
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
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


def _create_function_with_retry(
    ctx, function_name: str, role_arn: str, zip_path: str, timeout_s=90.0
):
    """create-function via CLI, retrying while the freshly-created role has not yet
    propagated (IAM eventual consistency). Registers cleanup on success."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = _run_aws(
                ctx,
                "lambda",
                "create-function",
                "--function-name",
                function_name,
                "--runtime",
                "python3.12",
                "--role",
                role_arn,
                "--handler",
                "index.handler",
                "--timeout",
                "30",
                "--zip-file",
                f"fileb://{zip_path}",
                "--tags",
                "sim2real=true",
            )
            ctx.on_cleanup(lambda: _delete_function_log_group(ctx, function_name))
            ctx.on_cleanup(lambda: _safe_delete_function(ctx, function_name))
            return resp
        except AssertionError as e:
            last_err = e
            time.sleep(3)
    raise AssertionError(
        f"create-function never succeeded (role propagation?): {last_err}"
    )


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


def _invoke_until_ok(
    ctx, function_name: str, payload: dict, timeout_s=90.0, interval_s=3.0
) -> dict:
    """Polls invocation until the handler reports ok=True (tolerates freshly-attached
    IAM policy propagation delay) or raises after timeout_s."""
    deadline = time.monotonic() + timeout_s
    last_body = None
    while time.monotonic() < deadline:
        result = _invoke_sync(ctx, function_name, payload)
        last_body = result["body"]
        if result["meta"].get("FunctionError") is None and last_body.get("ok") is True:
            return last_body
        time.sleep(interval_s)
    raise AssertionError(
        f"invocation never reported ok=True within {timeout_s}s; last body: {last_body}"
    )


def _get_verified_sender(ctx) -> str:
    """An address under the target's verified sending domain (_sending_domain)."""
    domain = _sending_domain(ctx, ctx.client("route53"), ctx.client("sesv2"))
    return f"{ctx.unique_name('sim2real-ses-sender-')}@{domain}"


_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


def _sending_domain(ctx, route53, sesv2):
    """The target's DNS baseline domain (its tagged public hosted zone, verified in SES); an account without one fails the check."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified for sending in {ctx.region}"
                )
                return domain
    raise AssertionError(
        "this account has no DNS baseline zone (a public hosted zone carrying the baseline "
        "tag, verified in SES) and so no sending domain; the check requires one"
    )


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across two consecutive reads 2 s apart. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
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
