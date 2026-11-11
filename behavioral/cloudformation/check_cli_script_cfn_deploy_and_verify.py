"""cli-script-cfn-deploy-and-verify."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-script-cfn-deploy-and-verify"

GROUP = "cli-script"

SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Bash script deploys a CFN stack, sends+receives a real message through the
    deployed queue via CLI, then deletes the stack and proves the queue is gone."""
    stack_name = _xname(ctx, "cfn-stk")
    queue_name = _xname(ctx, "cfn-sqs")
    probe_body = f"cfn-cli-probe-{stack_name}"
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": queue_name,
                        "Tags": _xsvc_tags_kv(),
                    },
                }
            },
            "Outputs": {"QueueUrl": {"Value": {"Ref": "Q"}}},
        }
    )
    ctx.on_cleanup(
        lambda: ctx.client("cloudformation").delete_stack(StackName=stack_name)
    )
    result = _run_script(
        ctx,
        f"""
        aws cloudformation create-stack \\
            --stack-name {stack_name} \\
            --template-body '{template}' \\
            --tags {_cfn_tags_cli_args()}

        aws cloudformation wait stack-create-complete --stack-name {stack_name}

        URL=$(aws cloudformation describe-stacks --stack-name {stack_name} \\
            --query "Stacks[0].Outputs[?OutputKey=='QueueUrl'].OutputValue" --output text)
        echo "URL:$URL"

        aws sqs send-message --queue-url "$URL" --message-body '{probe_body}' > /dev/null

        BODY=""
        for attempt in $(seq 1 5); do
            BODY=$(aws sqs receive-message --queue-url "$URL" --wait-time-seconds 5 \\
                --query 'Messages[0].Body' --output text)
            if [ "$BODY" != "None" ] && [ -n "$BODY" ]; then break; fi
        done
        echo "BODY:$BODY"

        aws cloudformation delete-stack --stack-name {stack_name}
        aws cloudformation wait stack-delete-complete --stack-name {stack_name}
    """,
        timeout_s=300.0,
    )
    lines = result.stdout.strip().split("\n")
    url_line = next(line for line in lines if line.startswith("URL:"))
    body_line = next(line for line in lines if line.startswith("BODY:"))
    queue_url = url_line[len("URL:") :]
    received_body = body_line[len("BODY:") :]
    assert queue_url and queue_url != "None", (
        f"Expected a queue URL in CFN output, got: {queue_url!r}"
    )
    assert received_body == probe_body, (
        f"Expected to receive the probe message {probe_body!r} through the "
        f"CFN-deployed queue, got {received_body!r}"
    )

    # The bash script already waited for stack-delete-complete; an independent
    # SDK read against SQS itself (not CFN's view of the stack) proves the
    # queue the stack created is actually gone and unusable, not just that the
    # stack's own status flipped.
    sqs = ctx.client("sqs")
    try:
        sqs.get_queue_url(QueueName=queue_name)
        raise AssertionError(
            f"Queue {queue_name} still resolvable via GetQueueUrl after "
            "stack delete-complete"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "AWS.SimpleQueueService.NonExistentQueue", (
            f"Expected NonExistentQueue looking up {queue_name} after "
            f"stack teardown, got {code}"
        )
        assert message == "The specified queue does not exist.", (
            f"Expected the exact NonExistentQueue message looking up {queue_name}, got {message!r}"
        )
    try:
        sqs.send_message(QueueUrl=queue_url, MessageBody="post-delete-probe")
        raise AssertionError(
            f"SendMessage to deleted queue {queue_url} unexpectedly succeeded"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "AWS.SimpleQueueService.NonExistentQueue", (
            f"Expected NonExistentQueue sending to deleted {queue_url}, got {code}"
        )
        assert message == "The specified queue does not exist.", (
            f"Expected the exact NonExistentQueue message sending to {queue_url}, got {message!r}"
        )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _cfn_tags_cli_args() -> str:
    return " ".join(f"Key={t['Key']},Value={t['Value']}" for t in _xsvc_tags_kv())


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    """Run a multi-line bash script (set -euo pipefail) with the run's AWS creds configured."""

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


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with the run's AWS creds + region in the
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
