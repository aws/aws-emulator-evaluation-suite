"""cdk-destroy-deletes-a-create-failed-stack-and-its-live-resources."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-destroy-deletes-a-create-failed-stack-and-its-live-resources"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs", "ssm"]

_APP = "cdk_no_rollback"
_GONE_BUDGET_S = 90.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`cdk destroy` of a stack parked in CREATE_FAILED by `--no-rollback` reaches DELETE_COMPLETE
    and deletes the queue and parameter the failed create had left live.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-cdk-dsf-")
    keep = "/" + ctx.unique_name("sim2real-cdk-dsf-keep-")
    queue = ctx.unique_name("sim2real-cdk-dsf-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region,
               "queue_name": queue, "param_name": keep, "broken": "1"}
    work = _stage_app(ctx)
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=keep), "ParameterNotFound"))
    ctx.on_cleanup(_teardown(lambda: _delete_queue(sqs, queue),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never", "--no-rollback"],
                   context)
    assert rc == 1, f"the failing deploy exited {rc}; output tail {out[-800:]!r}"
    parked = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    stack_id = parked["StackId"]
    assert parked["StackStatus"] == "CREATE_FAILED", f"the stack is {parked['StackStatus']!r}"
    url = sqs.get_queue_url(QueueName=queue)["QueueUrl"]
    value = ssm.get_parameter(Name=keep)["Parameter"]["Value"]
    assert value == "keep", f"the good parameter in the parked stack holds {value!r}"

    rc, out = _cdk(ctx, work, ["destroy", stack, "--force"], context)
    assert rc == 0, f"`cdk destroy` of the CREATE_FAILED stack exited {rc}; tail {out[-800:]!r}"
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status == "DELETE_COMPLETE", f"after `cdk destroy` the stack is {status!r}"
    assert _err(lambda: cfn.describe_stacks(StackName=stack)) == (
        "ValidationError", f"Stack with id {stack} does not exist"), "the destroyed stack still resolves"
    assert _err(lambda: ssm.get_parameter(Name=keep)) == ("ParameterNotFound", ""), (
        "the parameter the failed create left live survived `cdk destroy`"
    )
    gone = _queue_gone(sqs, url)
    assert gone == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"the queue the failed create left live answers {gone!r} after `cdk destroy`"
    )


def _queue_gone(sqs, url: str) -> tuple[str, str]:
    """The (code, message) GetQueueAttributes answers once the deleted queue stops resolving."""
    deadline = time.monotonic() + _GONE_BUDGET_S
    while True:
        try:
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        if time.monotonic() > deadline:
            raise AssertionError(f"the queue still answers {_GONE_BUDGET_S}s after the destroy")
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


def _err(fn) -> tuple[str, str]:
    """The (code, message) a call raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
