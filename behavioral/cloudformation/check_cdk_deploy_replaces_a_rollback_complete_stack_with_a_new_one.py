"""cdk-deploy-replaces-a-rollback-complete-stack-with-a-new-one."""
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

CHECK = "cdk-deploy-replaces-a-rollback-complete-stack-with-a-new-one"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_APP = "cdk_recreate_rollback_complete"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A failed first `cdk deploy` rolls the new stack back to ROLLBACK_COMPLETE; the fixed redeploy
    deletes that stack and creates a new one under the same name with a new StackId.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cdk-recr-")
    keep = "/" + ctx.unique_name("sim2real-cdk-recr-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region,
               "param_name": keep}
    work = _stage_app(ctx)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"],
                   {**context, "broken": "1"})
    assert rc == 1, f"the failing deploy exited {rc}; output tail {out[-800:]!r}"
    failed = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    old_id = failed["StackId"]
    assert failed["StackStatus"] == "ROLLBACK_COMPLETE", f"the failed create left {failed['StackStatus']!r}"
    bad_events = [e for e in _events(cfn, old_id) if e["LogicalResourceId"] == "Bad"]
    bad = bad_events[-1]
    reasons = [e.get("ResourceStatusReason") for e in bad_events
               if e["ResourceStatus"] == "CREATE_FAILED"]
    assert (bad["ResourceStatus"], reasons) == ("DELETE_COMPLETE", [
        f"{keep} already exists in stack {old_id}"]), (
        f"the colliding parameter's last event is {bad!r} and its failure reasons {reasons!r}"
    )

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"],
                   {**context, "broken": "0"})
    assert rc == 0, f"the fixed redeploy exited {rc}; output tail {out[-800:]!r}"
    fresh = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    stack_id_form = (rf"arn:aws:cloudformation:{re.escape(ctx.region)}:{ctx.account}:stack/"
                     rf"{re.escape(stack)}/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}"
                     r"-[0-9a-f]{12}")
    assert (fresh["StackStatus"], bool(re.fullmatch(stack_id_form, fresh["StackId"]))) == (
        "CREATE_COMPLETE", True), (
        f"the fixed redeploy left {fresh['StackStatus']!r} with StackId {fresh['StackId']!r}"
    )
    status = cfn.describe_stacks(StackName=old_id)["Stacks"][0]["StackStatus"]
    assert status == "DELETE_COMPLETE", f"the rolled-back stack it replaced is {status!r}"
    physical = {r["LogicalResourceId"]: r["PhysicalResourceId"]
                for r in cfn.describe_stack_resources(StackName=fresh["StackId"])["StackResources"]}
    assert physical == {"Keep": keep, "Bad": f"{keep}-fixed"}, f"the new stack holds {physical!r}"


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


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]][::-1]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
