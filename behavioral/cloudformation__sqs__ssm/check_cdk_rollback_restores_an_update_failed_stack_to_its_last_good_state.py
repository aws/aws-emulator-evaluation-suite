"""cdk-rollback-restores-an-update-failed-stack-to-its-last-good-state."""
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

CHECK = "cdk-rollback-restores-an-update-failed-stack-to-its-last-good-state"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs", "ssm"]

_APP = "cdk_rollback_update_failed"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`cdk rollback` on a stack a `--no-rollback` deploy left UPDATE_FAILED reaches
    UPDATE_ROLLBACK_COMPLETE, restoring the queue attribute and parameter value it had updated and
    deleting the parameter it had added.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-cdk-rb-")
    keep = "/" + ctx.unique_name("sim2real-cdk-rb-keep-")
    added = "/" + ctx.unique_name("sim2real-cdk-rb-added-")
    queue = ctx.unique_name("sim2real-cdk-rb-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region,
               "queue_name": queue, "param_name": keep, "added_name": added}
    work = _stage_app(ctx)
    for name in (keep, added):
        ctx.on_cleanup(_teardown(lambda n=name: ssm.delete_parameter(Name=n), "ParameterNotFound"))
    ctx.on_cleanup(_teardown(lambda: _delete_queue(sqs, queue),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"],
                   {**context, "variant": "1"})
    assert rc == 0, f"the first deploy exited {rc}; output tail {out[-800:]!r}"
    url = sqs.get_queue_url(QueueName=queue)["QueueUrl"]

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never", "--no-rollback"],
                   {**context, "variant": "2"})
    assert rc == 1, f"the failing update exited {rc}; output tail {out[-800:]!r}"
    status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    assert status == "UPDATE_FAILED", f"the --no-rollback update left the stack {status!r}"
    assert _state(sqs, ssm, url, keep, added) == ("60", "v2", "added"), (
        f"the parked update's effects are {_state(sqs, ssm, url, keep, added)!r}"
    )

    rc, out = _cdk(ctx, work, ["rollback", stack, "--no-validate-bootstrap-version"],
                   {**context, "variant": "2"})
    assert rc == 0, f"`cdk rollback` exited {rc}; output tail {out[-800:]!r}"
    stack_doc = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert stack_doc["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"`cdk rollback` left the stack {stack_doc['StackStatus']!r} "
        f"({stack_doc.get('StackStatusReason')!r})"
    )
    assert _state(sqs, ssm, url, keep, added) == ("30", "v1", ("ParameterNotFound", "")), (
        f"after `cdk rollback` the queue timeout, parameter and added parameter are "
        f"{_state(sqs, ssm, url, keep, added)!r}"
    )


def _state(sqs, ssm, url: str, keep: str, added: str) -> tuple:
    """(queue VisibilityTimeout, kept value, added value or its (code, message))."""
    timeout = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"]["VisibilityTimeout"]
    kept = ssm.get_parameter(Name=keep)["Parameter"]["Value"]
    try:
        extra = ssm.get_parameter(Name=added)["Parameter"]["Value"]
    except ClientError as exc:
        extra = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
    return timeout, kept, extra


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
