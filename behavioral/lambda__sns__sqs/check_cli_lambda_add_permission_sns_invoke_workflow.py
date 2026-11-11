"""cli-lambda-add-permission-sns-invoke-workflow."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-add-permission-sns-invoke-workflow"
GROUP = "cli-workflow"
SERVICES = ["lambda", "sns", "sqs"]

_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true"}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws cli `lambda add-permission` grants sns.amazonaws.com invoke rights; a
    subsequent SNS publish actually invokes the function, observed via a message the
    function forwards to a side-channel SQS queue (not merely a 200 from add-permission)."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-obs-"), tags=_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_name = ctx.unique_name("sim2real-role-")
    role_arn = _create_lambda_role(ctx, role_name, queue_arn)

    func_name = ctx.unique_name("sim2real-fn-")
    func_arn = _create_forwarder_function(ctx, func_name, role_arn, queue_url)

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-topic-"), Tags=_resource_tags_kv()
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=func_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    granted = _run_aws(
        ctx,
        "lambda", "add-permission",
        "--function-name", func_name,
        "--statement-id", "sns-invoke",
        "--action", "lambda:InvokeFunction",
        "--principal", "sns.amazonaws.com",
        "--source-arn", topic_arn,
    )
    assert "Statement" in granted, f"add-permission returned no Statement: {granted!r}"
    granted_statement = json.loads(granted["Statement"])
    assert granted_statement.get("Principal") == {"Service": "sns.amazonaws.com"}, (
        f"granted statement principal {granted_statement.get('Principal')!r} != "
        "{'Service': 'sns.amazonaws.com'}"
    )
    assert (
        granted_statement.get("Condition", {}).get("ArnLike", {}).get("AWS:SourceArn")
        == topic_arn
    ), (
        f"granted statement not scoped to {topic_arn!r}: "
        f"{granted_statement.get('Condition')!r}"
    )

    marker = ctx.unique_name("marker-")
    sns.publish(TopicArn=topic_arn, Message=marker)
    assert _wait_for_marker(ctx, queue_url, marker, timeout_s=60.0), (
        "forwarder Lambda was never invoked despite a granted sns.amazonaws.com "
        "InvokeFunction permission"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with leased AWS creds + region in the
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
    """Run a multi-line bash script (set -euo pipefail) with leased AWS creds configured."""

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


def _create_lambda_role(ctx, role_name: str, queue_arn: str) -> str:
    iam = ctx.client("iam")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_resource_tags_kv(),
    )["Role"]["Arn"]

    policy_name = f"{role_name}-policy"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_forwarder_function(ctx, func_name: str, role_arn: str, queue_url: str) -> str:
    lam = ctx.client("lambda")
    code = (
        "import os\n"
        "import boto3\n\n"
        "sqs = boto3.client('sqs')\n"
        "QUEUE_URL = os.environ['FORWARD_QUEUE_URL']\n\n"
        "def handler(event, context):\n"
        "    for record in event.get('Records', []):\n"
        "        message = record.get('Sns', {}).get('Message', '')\n"
        "        sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=message)\n"
        "    return {'forwarded': len(event.get('Records', []))}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as zf:
        zf.writestr("lambda_function.py", code)
    zip_bytes = buf.getvalue()

    func_arn = None
    last_error: Exception | None = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"FORWARD_QUEUE_URL": queue_url}},
                Tags=_resource_tags(),
            )
            func_arn = resp["FunctionArn"]
            break
        except ClientError as exc:
            # IAM role/assume-role propagation lag manifests as InvalidParameterValueException.
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_error = exc
            time.sleep(3)
    if func_arn is None:
        raise AssertionError(f"create_function never succeeded: {last_error}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))

    deadline = time.monotonic() + 90.0
    state = ""
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=func_name)["Configuration"]["State"]
        if state == "Active":
            break
        time.sleep(2)
    if state != "Active":
        raise AssertionError(f"function never became Active (last state={state!r})")
    return func_arn


def _wait_for_marker(ctx, queue_url: str, marker: str, timeout_s: float = 60.0) -> bool:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if msg["Body"] == marker:
                return True
    return False


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
