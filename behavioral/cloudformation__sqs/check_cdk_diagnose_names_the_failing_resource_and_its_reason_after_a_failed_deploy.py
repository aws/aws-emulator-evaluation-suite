"""cdk-diagnose-names-the-failing-resource-and-its-reason-after-a-failed-deploy."""
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

CHECK = "cdk-diagnose-names-the-failing-resource-and-its-reason-after-a-failed-deploy"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

_DEPLOY_TIMEOUT_S = 600.0
_DIAGNOSE_TIMEOUT_S = 180.0

_APP = """\
import aws_cdk as cdk
import aws_cdk.aws_sqs as sqs

app = cdk.App()
stack_name = app.node.try_get_context("stack_name")
visibility_timeout = int(app.node.try_get_context("visibility_timeout"))


class FailStack(cdk.Stack):
    def __init__(self, scope, cid, **kwargs) -> None:
        super().__init__(scope, cid, **kwargs)
        sqs.CfnQueue(self, "Queue", queue_name=f"{cid}-q",
                     visibility_timeout=visibility_timeout)


FailStack(app, stack_name, synthesizer=cdk.LegacyStackSynthesizer())
app.synth()
"""


@tags("axis:rejection", "cap:c2", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After `cdk deploy` of a stack whose only resource fails to create, `cdk diagnose` names that
    resource, its type and CloudFormation's own failure reason; for a healthy stack it reports none.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/ref-cli-cmd-diagnose.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkdiag-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    (work / "cdk.json").write_text(json.dumps({"app": f"{sys.executable} app.py"}))
    (work / "app.py").write_text(_APP)

    prefix = ctx.unique_name("sim2real-cdkdiag-")
    broken_stack = f"{prefix}-broken"
    healthy_stack = f"{prefix}-healthy"
    toolkit_stack = f"{prefix}-toolkit"
    deploy_flags = ["--require-approval", "never", "--toolkit-stack-name", toolkit_stack,
                    "--tags", f"sim2real={CHECK}"]

    # ---- 1. `cdk deploy` of a stack whose only resource SQS refuses to create -----------------
    # SQS caps VisibilityTimeout at 43200 s. The L1 CfnQueue passes 999999 through unvalidated,
    # so synth succeeds and the queue's CREATE fails in CloudFormation, which rolls the stack back.
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, broken_stack))
    rc, out = _cdk(ctx, work, ["deploy", broken_stack, *deploy_flags],
                   stack=broken_stack, visibility_timeout=999999, timeout_s=_DEPLOY_TIMEOUT_S)
    assert rc == 1, (
        f"`cdk deploy` of the stack with an out-of-range VisibilityTimeout exited {rc}, expected "
        f"1; output tail: {out[-1200:]!r}"
    )
    broken_status = cfn.describe_stacks(StackName=broken_stack)["Stacks"][0]["StackStatus"]
    assert broken_status == "ROLLBACK_COMPLETE", (
        f"the stack with an out-of-range VisibilityTimeout is at {broken_status!r} after the "
        f"failed deploy, expected ROLLBACK_COMPLETE"
    )
    reason = _create_failed_reason(cfn, broken_stack, _queue_logical_id(work, broken_stack))
    assert "VisibilityTimeout" in reason, (
        f"CloudFormation's own CREATE_FAILED reason for the Queue resource does not mention "
        f"VisibilityTimeout: {reason!r}"
    )

    # ---- 2. a healthy stack, deployed the same way, as the positive control ------------------
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, healthy_stack))
    rc, out = _cdk(ctx, work, ["deploy", healthy_stack, *deploy_flags],
                   stack=healthy_stack, visibility_timeout=30, timeout_s=_DEPLOY_TIMEOUT_S)
    assert rc == 0, f"`cdk deploy` of the healthy stack exited {rc}; output tail: {out[-1200:]!r}"
    healthy_status = cfn.describe_stacks(StackName=healthy_stack)["Stacks"][0]["StackStatus"]
    assert healthy_status == "CREATE_COMPLETE", (
        f"the healthy control stack is at {healthy_status!r}, expected CREATE_COMPLETE"
    )

    # ---- 3. cdk diagnose on the BROKEN stack names the resource, its type and the reason -----
    rc, out = _cdk(ctx, work, ["diagnose", broken_stack, "--unstable=diagnose"],
                   stack=broken_stack, visibility_timeout=999999, timeout_s=_DIAGNOSE_TIMEOUT_S)
    assert rc == 1, f"`cdk diagnose` on the failed stack exited {rc}, expected 1; output: {out!r}"
    assert f"{broken_stack}/Queue" in out, (
        f"`cdk diagnose` did not name the failing resource's construct path "
        f"{broken_stack}/Queue; output: {out!r}"
    )
    assert "AWS::SQS::Queue" in out, (
        f"`cdk diagnose` did not name the failing resource's type AWS::SQS::Queue; output: "
        f"{out!r}"
    )
    assert "VisibilityTimeout" in out, (
        f"`cdk diagnose` did not carry CloudFormation's own failure reason (it names "
        f"VisibilityTimeout); output: {out!r}"
    )
    assert "Resource updates failed" in out, (
        f"`cdk diagnose` did not report the stack as having failed resource updates; output: "
        f"{out!r}"
    )

    # ---- 4. cdk diagnose on the HEALTHY stack reports none -----------------------------------
    rc, out = _cdk(ctx, work, ["diagnose", healthy_stack, "--unstable=diagnose"],
                   stack=healthy_stack, visibility_timeout=30, timeout_s=_DIAGNOSE_TIMEOUT_S)
    assert rc == 0, f"`cdk diagnose` on the healthy stack exited {rc}, expected 0; output: {out!r}"
    assert "no issues found" in out, (
        f"`cdk diagnose` on a stack with no failures did not report 'no issues found'; output: "
        f"{out!r}"
    )
    assert "AWS::SQS::Queue" not in out, (
        f"`cdk diagnose` on the healthy stack named a resource anyway; output: {out!r}"
    )


def _cdk(ctx, work: Path, args: list[str], *, stack: str, visibility_timeout: int,
         timeout_s: float) -> tuple[int, str]:
    """Run `cdk <args>` against the app in *work*, returning `(returncode, stdout+stderr)`."""
    ctx.verify_account_safety()
    cmd = [
        "cdk", *args,
        "--ci", "--no-version-reporting", "--no-notices", "--no-color",
        "--context", f"stack_name={stack}",
        "--context", f"visibility_timeout={visibility_timeout}",
    ]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    return result.returncode, result.stdout + result.stderr


def _queue_logical_id(work: Path, stack: str) -> str:
    """The logical id CDK gave *stack*'s one AWS::SQS::Queue, from its synthesized template."""
    template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())
    queues = [lid for lid, r in template["Resources"].items() if r["Type"] == "AWS::SQS::Queue"]
    assert len(queues) == 1, f"stack {stack!r} lists queue resources {queues!r}, expected one"
    return queues[0]


def _create_failed_reason(cfn, stack_id: str, logical_id: str) -> str:
    """The `ResourceStatusReason` CloudFormation recorded for *logical_id*'s CREATE_FAILED event."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for event in page["StackEvents"]:
            if (event["LogicalResourceId"] == logical_id
                    and event["ResourceStatus"] == "CREATE_FAILED"):
                return str(event.get("ResourceStatusReason", ""))
    raise AssertionError(f"no CREATE_FAILED event found for {logical_id!r} in stack {stack_id!r}")


def _delete_stack_and_wait(cfn, stack: str, *, timeout_s: float = 300.0) -> None:
    """Delete *stack* by StackId if it exists, then poll to DELETE_COMPLETE."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last {last!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
