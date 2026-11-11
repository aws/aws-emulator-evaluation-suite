"""cdk-deploy-concurrency-2-still-orders-a-declared-stack-dependency."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cdk-deploy-concurrency-2-still-orders-a-declared-stack-dependency"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_DEPLOY_TIMEOUT_S = 300.0
_DESTROY_TIMEOUT_S = 300.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_concurrency"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`cdk deploy --all --concurrency 2` still finishes a stack before starting the one that
    declares a dependency on it, and every stack's SSM parameter reads back with its value.
    """
    ctx.verify_account_safety()
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    prefix = ctx.unique_name("sim2real-cdkconc-")
    stack_base = f"{prefix}-base"
    stack_dependent = f"{prefix}-dependent"
    stack_independent = f"{prefix}-independent"
    toolkit_stack = f"{prefix}-toolkit"
    param_base = ctx.unique_name("sim2real-cdkconc-base-")
    param_dependent = ctx.unique_name("sim2real-cdkconc-dep-")
    param_independent = ctx.unique_name("sim2real-cdkconc-ind-")
    expected_values = {param_base: "v-base", param_dependent: "v-dependent",
                       param_independent: "v-independent"}

    work = _stage_app(ctx, _APP)
    stacks = [stack_base, stack_dependent, stack_independent]
    ctx.on_cleanup(lambda: _teardown(ctx, stacks))

    _cdk(ctx, work, ["deploy", "--all", "--concurrency", "2", "--require-approval", "never",
                     "--toolkit-stack-name", toolkit_stack],
         {"account": ctx.account, "region": ctx.region,
          "stack_base": stack_base, "stack_dependent": stack_dependent,
          "stack_independent": stack_independent,
          "param_base": param_base, "param_dependent": param_dependent,
          "param_independent": param_independent,
          "value_base": "v-base", "value_dependent": "v-dependent",
          "value_independent": "v-independent"},
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    for stack in stacks:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        assert status == "CREATE_COMPLETE", (
            f"stack {stack!r} ended at {status!r}, expected CREATE_COMPLETE"
        )

    # ---- 1. THE HEADLINE: the declared dependency is still honored under concurrency 2 ---------
    base_done = _stack_level_event_time(cfn, stack_base, "CREATE_COMPLETE")
    dependent_start = _stack_level_event_time(cfn, stack_dependent, "CREATE_IN_PROGRESS")
    assert base_done <= dependent_start, (
        f"Base {stack_base!r} reached CREATE_COMPLETE at {base_done!r}, after Dependent "
        f"{stack_dependent!r} (which declares `add_dependency(base)`) started being created at "
        f"{dependent_start!r}; `--concurrency 2` must still finish a stack's dependency before "
        f"starting it"
    )

    # ---- 2. Each stack's parameter exists in SSM with the value its stack declared -------------
    for name, value in expected_values.items():
        parameter = ssm.get_parameter(Name=name)["Parameter"]
        assert (parameter["Type"], parameter["Value"]) == ("String", value), (
            f"SSM parameter {name!r} reads back as {(parameter['Type'], parameter['Value'])!r}, "
            f"expected ('String', {value!r}) as its stack declared"
        )


def _stack_level_event_time(cfn, stack: str, status: str):
    """The Timestamp of the newest stack-level (AWS::CloudFormation::Stack) event at *status*."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        for event in page["StackEvents"]:
            if (event.get("ResourceType") == "AWS::CloudFormation::Stack"
                    and event.get("ResourceStatus") == status):
                return event["Timestamp"]
    raise AssertionError(f"no stack-level event at status {status!r} found for {stack!r}")


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


def _is_stack_not_found(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    return (error.get("Code") == "ValidationError"
            and "does not exist" in str(error.get("Message", "")))


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
