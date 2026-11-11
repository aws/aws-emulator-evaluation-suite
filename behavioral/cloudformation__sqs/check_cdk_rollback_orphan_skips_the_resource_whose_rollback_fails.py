"""cdk-rollback-orphan-skips-the-resource-whose-rollback-fails."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-rollback-orphan-skips-the-resource-whose-rollback-fails"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

_APP = "cdk_rollback_skip_failed_resource"
_GONE_BUDGET_S = 90.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """With the updated queue deleted out of band, `cdk rollback` of the UPDATE_FAILED stack fails
    on that queue and leaves UPDATE_ROLLBACK_FAILED; `cdk rollback --orphan Queue` skips it and
    completes the rollback, deleting the parameter the failed update added.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack = ctx.unique_name("sim2real-cdk-orph-")
    queue = ctx.unique_name("sim2real-cdk-orph-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region,
               "queue_name": queue,
               "added_name": "/" + ctx.unique_name("sim2real-cdk-orph-added-")}
    work = _stage_app(ctx)
    ctx.on_cleanup(_teardown(lambda: _delete_queue(sqs, queue),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"],
                   {**context, "variant": "1"})
    assert rc == 0, f"the first deploy exited {rc}; output tail {out[-800:]!r}"
    stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    url = sqs.get_queue_url(QueueName=queue)["QueueUrl"]
    v2 = {**context, "variant": "2"}
    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never", "--no-rollback"], v2)
    assert rc == 1, f"the failing update exited {rc}; output tail {out[-800:]!r}"
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status == "UPDATE_FAILED", f"the --no-rollback update left the stack {status!r}"

    sqs.delete_queue(QueueUrl=url)
    gone = _queue_gone(sqs, url)
    assert gone == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"the deleted queue answers {gone!r}"
    )

    rc, out = _cdk(ctx, work, ["rollback", stack, "--no-validate-bootstrap-version"], v2)
    assert rc == 1, f"`cdk rollback` with the queue gone exited {rc}; output tail {out[-800:]!r}"
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status == "UPDATE_ROLLBACK_FAILED", f"the failed rollback left the stack {status!r}"
    reason = _last_event(cfn, stack_id, "Queue").get("ResourceStatusReason") or ""
    assert re.fullmatch(
        r'Resource handler returned message: "The specified queue does not exist\. \(Service: Sqs, '
        r'Status Code: 400, Request ID: [0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)" '
        r'\(RequestToken: [0-9a-f-]{36}, '
        r"HandlerErrorCode: NotFound\)", reason), f"the queue's rollback failed with {reason!r}"

    rc, out = _cdk(ctx, work, ["rollback", stack, "--orphan", "Queue", "--no-validate-bootstrap-version"], v2)
    assert rc == 0, f"`cdk rollback --orphan Queue` exited {rc}; output tail {out[-800:]!r}"
    final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert final["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"`cdk rollback --orphan` left the stack {final['StackStatus']!r} "
        f"({final.get('StackStatusReason')!r})"
    )
    added = _last_event(cfn, stack_id, "Added")["ResourceStatus"]
    assert added == "DELETE_COMPLETE", f"the parameter the failed update added ended {added!r}"


def _queue_gone(sqs, url: str) -> tuple[str, str]:
    """The (code, message) GetQueueAttributes answers once the deleted queue stops resolving."""
    deadline = time.monotonic() + _GONE_BUDGET_S
    while True:
        try:
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        if time.monotonic() > deadline:
            raise AssertionError(f"the queue still answers {_GONE_BUDGET_S}s after its delete")
        # SQS documents up to 60 s before a deleted queue stops answering.
        time.sleep(5.0)


def _stage_app(ctx) -> Path:
    """Copy the CDK app into a temp dir so cdk.out stays out of the app directory."""
    source = Path(__file__).parent / "deployments" / _APP
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is missing app.py or cdk.json"
    )
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdk-app-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(source, work / _APP, ignore=shutil.ignore_patterns("cdk.out", "__pycache__"))
    return work / _APP


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *,
         timeout_s: float = 600.0) -> tuple[int, str]:
    """Run the CDK CLI against the target; returns (exit code, stdout + stderr)."""
    cmd = ["cdk", *args, "--app", f"{sys.executable} app.py", "--ci", "--no-color",
           "--no-notices", "--no-version-reporting"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    done = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    return done.returncode, done.stdout + done.stderr


def _last_event(cfn, stack_id: str, logical_id: str) -> dict:
    """The newest stack event for one logical id."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for event in page["StackEvents"]:
            if event["LogicalResourceId"] == logical_id:
                return event
    raise AssertionError(f"no stack event names {logical_id!r}")


def _delete_queue(sqs, name: str) -> None:
    sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=name)["QueueUrl"])


def _delete_stack(cfn, name: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE; a stack never created is a no-op."""
    try:
        stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    stack_id = stack["StackId"]
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {name} teardown ended {status!r}")
        time.sleep(5.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
