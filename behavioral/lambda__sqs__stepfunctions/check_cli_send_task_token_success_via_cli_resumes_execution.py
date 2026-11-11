"""cli-send-task-token-success-via-cli-resumes-execution."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-send-task-token-success-via-cli-resumes-execution"
GROUP = "cli-workflow"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A state machine using sqs:sendMessage.waitForTaskToken publishes its task token to SQS;
    capturing that token via the SDK and resuming with `aws stepfunctions send-task-success`
    (CLI) drives the execution to SUCCEEDED with the CLI-supplied output."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-token-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-token-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_fully(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="send-to-queue",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
        }),
    )
    _wait_role_assumable(iam, role_name)

    sm_name = ctx.unique_name("sim2real-token-sm-")
    definition = json.dumps({
        "Comment": "waits for an external SendTaskSuccess",
        "StartAt": "WaitForToken",
        "States": {
            "WaitForToken": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
                "Parameters": {
                    "QueueUrl": queue_url,
                    "MessageBody": {"TaskToken.$": "$$.Task.Token", "Input.$": "$"},
                },
                "Retry": [
                    {"ErrorEquals": ["States.ALL"], "IntervalSeconds": 2, "MaxAttempts": 6, "BackoffRate": 2.0}
                ],
                "End": True,
            }
        },
    })
    sm_arn = _create_state_machine_with_retry(sfn, sm_name, definition, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"job": "resume-me"})
    )["executionArn"]

    # capture the task token from the queue, via SDK
    token = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and token is None:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            token = body["TaskToken"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    assert token, "task token never arrived on the queue"

    # resume the execution via the aws CLI
    _run_aws(
        ctx, "stepfunctions", "send-task-success",
        "--task-token", token, "--task-output", json.dumps({"resumedBy": "cli"}),
    )

    def _describe():
        return sfn.describe_execution(executionArn=exec_arn)

    result = _poll_until(_describe, lambda r: r["status"] != "RUNNING", timeout_s=30.0, interval_s=2.0)
    assert result["status"] == "SUCCEEDED", f"execution ended in {result['status']}: {result.get('error')}"
    output = json.loads(result["output"])
    assert output == {"resumedBy": "cli"}, f"expected CLI-supplied output {{'resumedBy': 'cli'}}, execution output was {output}"


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


def _wait_role_assumable(iam_client, role_name, timeout_s=25.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam_client.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(2)
    raise AssertionError(f"role {role_name} never became visible")


def _delete_role_fully(iam_client, role_name):
    try:
        for pname in iam_client.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam_client.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam_client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam_client.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_state_machine_with_retry(sfn_client, name, definition, role_arn, timeout_s=60.0):
    """states.amazonaws.com trust may not be assumable immediately after CreateRole; retry."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sfn_client.create_state_machine(name=name, definition=definition, roleArn=role_arn)["stateMachineArn"]
        except Exception as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"create_state_machine never succeeded: {last_err}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
