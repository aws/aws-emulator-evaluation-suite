"""cdk-deploy-method-direct-creates-and-updates-without-a-change-set."""
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

CHECK = "cdk-deploy-method-direct-creates-and-updates-without-a-change-set"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_APP = "cdk_deploy_method_direct"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`cdk deploy --method=direct` creates and then updates the stack with no change set behind
    either operation, while a change-set deploy of the same stack records its named change set's
    id as the stack's ChangeSetId and then deletes the change set itself.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cdk-direct-")
    change_set = ctx.unique_name("sim2real-cdk-direct-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region}
    work = _stage_app(ctx)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    stack_id = None
    for variant, status in (("1", "CREATE_COMPLETE"), ("2", "UPDATE_COMPLETE")):
        rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never",
                                   "--method=direct"], {**context, "variant": variant})
        assert rc == 0, f"direct deploy {variant} exited {rc}; output tail {out[-800:]!r}"
        described = cfn.describe_stacks(StackName=stack_id or stack)["Stacks"][0]
        stack_id = described["StackId"]
        got = (described["StackStatus"], described.get("ChangeSetId"), _outputs(described))
        assert got == (status, None, {"Variant": variant}), (
            f"after direct deploy {variant} the stack is {got!r}"
        )
        listed = [s for page in cfn.get_paginator("list_change_sets").paginate(StackName=stack_id)
                  for s in page["Summaries"]]
        assert listed == [], f"after direct deploy {variant} the stack lists change sets {listed!r}"

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never",
                               "--change-set-name", change_set], {**context, "variant": "3"})
    assert rc == 0, f"the change-set deploy exited {rc}; output tail {out[-800:]!r}"
    described = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    cs_id = described.get("ChangeSetId")
    got = (described["StackStatus"], _outputs(described))
    assert got == ("UPDATE_COMPLETE", {"Variant": "3"}), (
        f"after the change-set deploy the stack is {got!r}"
    )
    cs_id_pattern = (
        f"arn:aws:cloudformation:{re.escape(ctx.region)}:{re.escape(ctx.account)}:"
        rf"changeSet/{re.escape(change_set)}/[0-9a-f-]+"
    )
    assert cs_id is not None and re.fullmatch(cs_id_pattern, cs_id), (
        f"the stack's recorded ChangeSetId is {cs_id!r}, expected to match {cs_id_pattern!r}"
    )
    gone = _err(lambda: cfn.describe_change_set(StackName=stack_id, ChangeSetName=change_set))
    assert gone == ("ChangeSetNotFound", f"ChangeSet [{change_set}] does not exist"), (
        f"the executed change set should have been cleaned up, but describing it gave {gone!r}"
    )
    listed = [s for page in cfn.get_paginator("list_change_sets").paginate(StackName=stack_id)
              for s in page["Summaries"]]
    assert listed == [], f"after the change-set deploy the stack lists change sets {listed!r}"


def _outputs(described: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _err(fn) -> tuple[str, str]:
    """The (code, message) a call raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
