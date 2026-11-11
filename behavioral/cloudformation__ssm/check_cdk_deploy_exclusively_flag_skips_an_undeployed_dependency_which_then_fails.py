"""cdk-deploy-exclusively-flag-skips-an-undeployed-dependency-which-then-fails."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cdk-deploy-exclusively-flag-skips-an-undeployed-dependency-which-then-fails"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_DEPLOY_TIMEOUT_S = 300.0
_DESTROY_TIMEOUT_S = 300.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_exclusively"


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """`cdk deploy Dependent --exclusively` deploys only the named stack, never the Base stack
    it depends on; left undeployed, Base's export is missing and Dependent's own create fails.
    """
    ctx.verify_account_safety()
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    prefix = ctx.unique_name("sim2real-cdkexcl-")
    stack_base = f"{prefix}-base"
    stack_dependent = f"{prefix}-dependent"
    toolkit_stack = f"{prefix}-toolkit"
    param_base = ctx.unique_name("sim2real-cdkexcl-base-")
    param_dependent = ctx.unique_name("sim2real-cdkexcl-dep-")
    value_base = ctx.unique_name("vbase-")

    work = _stage_app(ctx, _APP)
    ctx.on_cleanup(lambda: _teardown(ctx, [stack_base, stack_dependent]))
    base_context = {
        "account": ctx.account, "region": ctx.region, "stack_prefix": prefix,
        "param_base": param_base, "param_dependent": param_dependent, "value_base": value_base,
    }
    deploy_flags = ["--require-approval", "never", "--toolkit-stack-name", toolkit_stack]

    # ---- 1. NEGATIVE: `--exclusively` leaves Base undeployed; Dependent's create then fails ----
    rc, _ = _cdk(ctx, work, ["deploy", stack_dependent, "--exclusively", *deploy_flags],
                base_context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
    assert rc != 0, (
        f"`cdk deploy {stack_dependent} --exclusively` exited 0 while Base {stack_base!r} was "
        f"never deployed and Dependent imports its export; expected the create to fail"
    )
    assert _stack_absent(cfn, stack_base), (
        f"Base {stack_base!r} exists after `cdk deploy {stack_dependent} --exclusively`; "
        f"`--exclusively` must deploy only the named stack, never a dependency it did not name"
    )
    dependent_status = cfn.describe_stacks(StackName=stack_dependent)["Stacks"][0]["StackStatus"]
    assert dependent_status == "ROLLBACK_COMPLETE", (
        f"Dependent {stack_dependent!r} ended at {dependent_status!r}, expected ROLLBACK_COMPLETE "
        f"after a first create that failed with no prior successful resources"
    )
    failure_reason = _latest_reason(cfn, stack_dependent)
    expected_fragment = f"No export named {prefix}-base"
    assert failure_reason.startswith(expected_fragment), (
        f"Dependent {stack_dependent!r}'s failure reason was {failure_reason!r}, expected it to "
        f"start with {expected_fragment!r} naming the missing export from the undeployed Base"
    )

    # ---- 2. Clear Dependent's failed rollback before the positive control ----------------------
    _delete_stack_and_wait(ctx, stack_dependent, timeout_s=_DESTROY_TIMEOUT_S)

    # ---- 3. POSITIVE CONTROL: without `--exclusively`, the dependency is auto-included ---------
    _cdk(ctx, work, ["deploy", stack_dependent, *deploy_flags], base_context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    ssm = ctx.client("ssm")
    base_status = cfn.describe_stacks(StackName=stack_base)["Stacks"][0]["StackStatus"]
    assert base_status == "CREATE_COMPLETE", (
        f"Base {stack_base!r} ended at {base_status!r} after deploying Dependent without "
        f"`--exclusively`, expected CREATE_COMPLETE — the default must auto-include the "
        f"dependency it skipped in step 1"
    )
    imported_value = ssm.get_parameter(Name=param_dependent)["Parameter"]["Value"]
    assert imported_value == value_base, (
        f"Dependent's parameter {param_dependent!r} holds {imported_value!r}, expected the "
        f"value imported from Base, {value_base!r}"
    )


def _latest_reason(cfn, stack: str) -> str:
    """The most recent stack-level ResourceStatusReason, which carries the failure message."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        for event in page["StackEvents"]:
            if event.get("ResourceType") == "AWS::CloudFormation::Stack":
                reason = event.get("ResourceStatusReason") or ""
                if reason:
                    return reason
    raise AssertionError(f"no stack-level event with a ResourceStatusReason found for {stack!r}")


def _is_stack_not_found(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    return (error.get("Code") == "ValidationError"
            and "does not exist" in str(error.get("Message", "")))


def _stack_absent(cfn, stack: str) -> bool:
    try:
        cfn.describe_stacks(StackName=stack)
    except ClientError as exc:
        if _is_stack_not_found(exc):
            return True
        raise
    return False


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present="
        f"{(source / 'app.py').is_file()}, cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1200:]!r}"
        )
    return result.returncode, output


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        found = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    except ClientError as exc:
        if _is_stack_not_found(exc):
            return
        raise
    stack_id = found["StackId"]
    if found["StackStatus"] == "DELETE_COMPLETE":
        return
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
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _teardown(ctx, stacks: list[str]) -> None:
    """Delete every stack this check created, dependent before base; collect-then-raise so one
    failing delete never stops the rest from being attempted."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    for stack in reversed(stacks):
        try:
            _delete_stack_and_wait(ctx, stack, timeout_s=max(30.0, deadline - time.monotonic()))
        except Exception as exc:  # noqa: BLE001 — collected below, the loop's end always raises
            problems.append(f"stack {stack}: {exc!r}")
    if problems:
        raise AssertionError("teardown left residue: " + "; ".join(problems))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
