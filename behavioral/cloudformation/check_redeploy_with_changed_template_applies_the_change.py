"""redeploy-with-changed-template-applies-the-change."""
from __future__ import annotations

import json
import os
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "redeploy-with-changed-template-applies-the-change"
GROUP = "cli-roundtrip"
SERVICES = ["cloudformation"]

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second `aws cloudformation deploy` of a template that adds a resource, run against the
    stack the first `deploy` created, reaches UPDATE_COMPLETE and the added queue really sends
    and receives a message -- not just that the CLI exits 0."""
    require_tools("aws")

    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-behav-redeploy-")
    q1 = ctx.unique_name("sim2real-behav-redeploy-q1-")
    q2 = ctx.unique_name("sim2real-behav-redeploy-q2-")

    template_path = _write_template(_template({"Q1": q1}))
    ctx.on_cleanup(lambda: os.unlink(template_path) if os.path.exists(template_path) else None)

    # Registered BEFORE the first deploy: a deploy that fails or times out still leaves a stack.
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_name))
    _deploy(ctx, stack_name, template_path, tag=f"sim2real:check={CHECK}")
    status = _stack_status(cfn, stack_name)
    assert status == "CREATE_COMPLETE", f"first deploy: expected CREATE_COMPLETE, got {status!r}"
    q1_url = sqs.get_queue_url(QueueName=q1)["QueueUrl"]

    template_path_v2 = _write_template(_template({"Q1": q1, "Q2": q2}))
    try:
        _deploy(ctx, stack_name, template_path_v2, tag=f"sim2real:check={CHECK}")
    finally:
        os.unlink(template_path_v2)

    status = _stack_status(cfn, stack_name)
    assert status == "UPDATE_COMPLETE", f"second deploy: expected UPDATE_COMPLETE, got {status!r}"
    resources = {
        r["LogicalResourceId"]: r["ResourceStatus"]
        for r in cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    }
    assert resources == {"Q1": "CREATE_COMPLETE", "Q2": "CREATE_COMPLETE"}, (
        f"expected Q1 and Q2 both CREATE_COMPLETE, got {resources!r}"
    )

    # The change the second deploy applied is a resource that really exists at SQS, not
    # merely a stack event: round-trip a message through it.
    q2_url = sqs.get_queue_url(QueueName=q2)["QueueUrl"]
    body = f"sim2real-probe-{q2}"
    sqs.send_message(QueueUrl=q2_url, MessageBody=body)
    received = _receive_one(sqs, q2_url, timeout_s=30)
    assert received == body, f"expected to receive {body!r} from the deployed queue, got {received!r}"

    # Q1 is untouched by the second deploy.
    assert sqs.get_queue_url(QueueName=q1)["QueueUrl"] == q1_url, "Q1's URL changed across the redeploy"

    # Delete the stack in-band, as a graded step, and confirm both queues are really gone.
    cfn.delete_stack(StackName=stack_name)
    final = _wait_terminal(cfn, stack_name, ("DELETE_COMPLETE", "DELETE_FAILED"))
    assert final == "DELETE_COMPLETE", f"stack delete ended {final!r}"
    for name, url in (("Q1", q1_url), ("Q2", q2_url)):
        code, msg = _error_code_and_message(
            lambda url=url: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])
        )
        assert (code, msg) == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
            f"{name} ({url}) should be gone after the stack delete, got ({code!r}, {msg!r})"
        )


def _template(queues: dict) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                logical: {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": name}}
                for logical, name in queues.items()
            },
        }
    )


def _write_template(body: str) -> str:
    fd, path = tempfile.mkstemp(prefix="sim2real-redeploy-", suffix=".json")
    with os.fdopen(fd, "w") as f:
        f.write(body)
    return path


def _deploy(ctx, stack_name: str, template_path: str, *, tag: str, timeout_s: float = 300.0) -> None:
    import subprocess

    ctx.verify_account_safety()
    result = subprocess.run(
        [
            "aws", "cloudformation", "deploy",
            "--stack-name", stack_name,
            "--template-file", template_path,
            "--tags", tag,
        ],
        env=ctx.subprocess_env(),
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    assert result.returncode == 0, (
        f"`aws cloudformation deploy` failed (rc={result.returncode}): {result.stderr[-800:]}"
    )


def _stack_status(cfn, name: str) -> str:
    return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]


def _wait_terminal(cfn, name: str, terminal, timeout_s: float = 180.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = _stack_status(cfn, name)
        except ClientError as exc:
            if "does not exist" in str(exc) and "DELETE_COMPLETE" in terminal:
                return "DELETE_COMPLETE"
            raise
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} did not reach {terminal} within {timeout_s}s (last={last!r})")


def _receive_one(sqs, url: str, *, timeout_s: float = 30.0) -> str | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5,
        ).get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]["Body"]
    return None


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("the call succeeded; expected it to be rejected")


def _delete_stack(ctx, cfn, name: str) -> None:
    try:
        status = _stack_status(cfn, name)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=name)
    final = _wait_terminal(cfn, name, ("DELETE_COMPLETE", "DELETE_FAILED"), timeout_s=300.0)
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {name} did not reach DELETE_COMPLETE: {final!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
