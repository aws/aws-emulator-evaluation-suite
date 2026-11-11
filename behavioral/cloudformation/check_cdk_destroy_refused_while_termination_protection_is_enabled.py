"""cdk-destroy-refused-while-termination-protection-is-enabled."""
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

CHECK = "cdk-destroy-refused-while-termination-protection-is-enabled"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_APP = "cdk_termination_protection"


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack deployed with termination_protection refuses `cdk destroy` and DeleteStack with a
    ValidationError and stays CREATE_COMPLETE; after a deploy turns protection off, destroy succeeds.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cdk-term-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region}
    work = _stage_app(ctx)
    ctx.on_cleanup(lambda: _unprotect_and_delete(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never",
                               "--tags", f"sim2real={CHECK}"],
                   {**context, "protected": "1"})
    assert rc == 0, f"the protected deploy exited {rc}; output tail {out[-800:]!r}"
    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    stack_id = described["StackId"]
    assert (described["StackStatus"], described["EnableTerminationProtection"]) == (
        "CREATE_COMPLETE", True), f"the protected stack is {described['StackStatus']!r}"

    rc, out = _cdk(ctx, work, ["destroy", stack, "--force"], {**context, "protected": "1"})
    assert rc == 1, f"`cdk destroy` of the protected stack exited {rc}; output tail {out[-800:]!r}"
    refused = _err(lambda: cfn.delete_stack(StackName=stack))
    assert refused == (
        "ValidationError",
        f"Stack [{stack}] cannot be deleted while TerminationProtection is enabled",
    ), f"DeleteStack on the protected stack gave {refused!r}"
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"the refused deletes left the stack {status!r}"

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never",
                               "--tags", f"sim2real={CHECK}"],
                   {**context, "protected": "0"})
    assert rc == 0, f"the unprotecting deploy exited {rc}; output tail {out[-800:]!r}"
    described = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert described["EnableTerminationProtection"] is False, (
        "the deploy with termination_protection off left protection enabled"
    )
    rc, out = _cdk(ctx, work, ["destroy", stack, "--force"], {**context, "protected": "0"})
    assert rc == 0, f"`cdk destroy` of the unprotected stack exited {rc}; tail {out[-800:]!r}"
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status == "DELETE_COMPLETE", f"after `cdk destroy` the stack is {status!r}"


def _unprotect_and_delete(cfn, name: str) -> None:
    """Turn termination protection off if the stack still exists, then delete it."""
    try:
        stack_id = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    cfn.update_termination_protection(StackName=stack_id, EnableTerminationProtection=False)
    _delete_stack(cfn, stack_id)


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
