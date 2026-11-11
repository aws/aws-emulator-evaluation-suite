"""cdk-deploy-no-rollback-keeps-create-failed-then-fixed-redeploy-completes."""
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

CHECK = "cdk-deploy-no-rollback-keeps-create-failed-then-fixed-redeploy-completes"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs", "ssm"]

_APP = "cdk_no_rollback"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`cdk deploy --no-rollback` of a failing app exits 1 and leaves the new stack CREATE_FAILED
    with its good queue and parameter live; the fixed redeploy updates the same stack to
    UPDATE_COMPLETE without re-creating either.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-cdk-norb-")
    keep = "/" + ctx.unique_name("sim2real-cdk-norb-keep-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region,
               "queue_name": ctx.unique_name("sim2real-cdk-norb-"), "param_name": keep}
    work = _stage_app(ctx)

    for name in (keep, f"{keep}-fixed"):
        ctx.on_cleanup(_teardown(lambda n=name: ssm.delete_parameter(Name=n), "ParameterNotFound"))
    ctx.on_cleanup(_teardown(lambda: _delete_queue(sqs, context["queue_name"]),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never", "--no-rollback"],
                   {**context, "broken": "1"})
    assert rc == 1, f"the failing deploy exited {rc}; output tail {out[-800:]!r}"
    parked = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    stack_id = parked["StackId"]
    got = (parked["StackStatus"], parked.get("StackStatusReason"), parked.get("DisableRollback"))
    assert got == ("CREATE_FAILED", "The following resource(s) failed to create: [Bad]. ", True), (
        f"after `cdk deploy --no-rollback` failed the stack is {got!r}"
    )
    bad = _last_event(cfn, stack_id, "Bad")
    assert (bad["ResourceStatus"], bad.get("ResourceStatusReason")) == (
        "CREATE_FAILED",
        f"{keep} already exists in stack {stack_id}",
    ), f"the colliding parameter's last event is {bad!r}"
    url = sqs.get_queue_url(QueueName=context["queue_name"])["QueueUrl"]
    born = _created(sqs, url)
    kept = ssm.get_parameter(Name=keep)["Parameter"]
    assert (kept["Value"], kept["Version"]) == ("keep", 1), f"the good parameter is {kept!r}"

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never", "--no-rollback"],
                   {**context, "broken": "0"})
    assert rc == 0, f"the fixed redeploy exited {rc}; output tail {out[-800:]!r}"
    fixed = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert (fixed["StackId"], fixed["StackStatus"]) == (stack_id, "UPDATE_COMPLETE"), (
        f"the fixed redeploy left {fixed['StackStatus']!r} on "
        f"{'the same' if fixed['StackId'] == stack_id else 'a new'} stack"
    )
    assert _created(sqs, url) == born, "the queue was re-created by the fixed redeploy"
    kept = ssm.get_parameter(Name=keep)["Parameter"]
    assert (kept["Value"], kept["Version"]) == ("keep", 1), f"the good parameter was rewritten: {kept!r}"
    value = ssm.get_parameter(Name=f"{keep}-fixed")["Parameter"]["Value"]
    assert value == "bad", f"the fixed parameter holds {value!r}, expected 'bad'"


def _created(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["CreatedTimestamp"])[
        "Attributes"]["CreatedTimestamp"]


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
