"""cdk-import-adopts-an-existing-queue-and-refuses-a-missing-one."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-import-adopts-an-existing-queue-and-refuses-a-missing-one"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

_APP = "cdk_import_queue"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`cdk import` mapped to a queue URL that names no queue fails and leaves the stack as it was;
    mapped to a queue created outside CloudFormation it adopts that same queue, not a new one.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-existing-stack.html
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack = ctx.unique_name("sim2real-cdk-imp-")
    queue = ctx.unique_name("sim2real-cdk-imp-")
    missing = ctx.unique_name("sim2real-cdk-imp-missing-")
    base = {"stack_name": stack, "account": ctx.account, "region": ctx.region}
    work = _stage_app(ctx)

    url = sqs.create_queue(QueueName=queue, Attributes={"VisibilityTimeout": "45"},
                           tags={"sim2real-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    born = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["CreatedTimestamp"])[
        "Attributes"]["CreatedTimestamp"]
    missing_url = url[: -len(queue)] + missing
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"],
                   {**base, "queue_name": queue, "with_queue": "0"})
    assert rc == 0, f"the first deploy exited {rc}; output tail {out[-800:]!r}"
    stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]

    rc, out = _cdk(ctx, work, ["import", stack, "--resource-mapping-inline",
                               json.dumps({"Queue": {"QueueUrl": missing_url}})],
                   {**base, "queue_name": missing, "with_queue": "1"})
    assert rc == 1, f"`cdk import` of a missing queue exited {rc}; output tail {out[-800:]!r}"
    failed_cs = [c for c in cfn.list_change_sets(StackName=stack_id)["Summaries"]
                 if c["Status"] == "FAILED"]
    assert len(failed_cs) == 1, f"expected one FAILED change set, got {failed_cs!r}"
    described_cs = cfn.describe_change_set(StackName=stack_id,
                                           ChangeSetName=failed_cs[0]["ChangeSetId"])
    assert (described_cs["Status"], described_cs["StatusReason"]) == (
        "FAILED",
        f"Resource of type 'AWS::SQS::Queue' with identifier '{missing_url}' was not found.",
    ), f"the missing queue's change set is {described_cs!r}"
    after = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert (after, _resources(cfn, stack_id)) == ("CREATE_COMPLETE", {"Handle": "CREATE_COMPLETE"}), (
        f"the refused import left the stack {after!r} with {_resources(cfn, stack_id)!r}"
    )

    rc, out = _cdk(ctx, work, ["import", stack, "--resource-mapping-inline",
                               json.dumps({"Queue": {"QueueUrl": url}})],
                   {**base, "queue_name": queue, "with_queue": "1"})
    assert rc == 0, f"`cdk import` of the existing queue exited {rc}; output tail {out[-800:]!r}"
    after = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert after == "IMPORT_COMPLETE", f"the import left the stack {after!r}"
    # The import applies stack-level tags to the imported resource as an update of its own.
    adopted = _poll_until(
        lambda: cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Queue")[
            "StackResourceDetail"],
        lambda r: _past_import(r["ResourceStatus"]),
        timeout_s=180.0, interval_s=5.0,
        description=f"the imported queue's stack-level tag update on {stack}")
    assert (adopted["PhysicalResourceId"], adopted["ResourceStatus"]) == (url, "UPDATE_COMPLETE"), (
        f"the imported queue's stack resource is {adopted!r}"
    )
    again = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["CreatedTimestamp"])[
        "Attributes"]["CreatedTimestamp"]
    assert again == born, f"the import re-created the queue: CreatedTimestamp {born!r} -> {again!r}"


def _past_import(status: str) -> bool:
    """True once the resource has left its import states for a terminal status."""
    return not status.endswith("_IN_PROGRESS") and status != "IMPORT_COMPLETE"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _resources(cfn, stack_id: str) -> dict[str, str]:
    """{logical id: status} of the stack's resources."""
    return {r["LogicalResourceId"]: r["ResourceStatus"]
            for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]}


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
