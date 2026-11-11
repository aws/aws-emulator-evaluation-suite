"""cdk-deploy-outputs-file-matches-describe-stacks-outputs-for-every-deployed-stack."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cdk-deploy-outputs-file-matches-describe-stacks-outputs-for-every-deployed-stack"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_DEPLOY_TIMEOUT_S = 300.0
_DESTROY_TIMEOUT_S = 300.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_outputs_file"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`cdk deploy --outputs-file` writes, for every stack named in that one deploy, exactly the
    OutputKey/OutputValue pairs DescribeStacks reports, and they match the SSM parameter itself.
    """
    ctx.verify_account_safety()
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    prefix = ctx.unique_name("sim2real-cdkout-")
    stack_a = f"{prefix}-a"
    stack_b = f"{prefix}-b"
    toolkit_stack = f"{prefix}-toolkit"
    param_a = ctx.unique_name("sim2real-cdkout-a-")
    param_b = ctx.unique_name("sim2real-cdkout-b-")
    value_a1 = ctx.unique_name("va1-")
    value_b1 = ctx.unique_name("vb1-")
    value_a2 = ctx.unique_name("va2-")

    work = _stage_app(ctx, _APP)
    ctx.on_cleanup(lambda: _teardown(ctx, [stack_a, stack_b]))
    deploy_flags = ["--require-approval", "never", "--toolkit-stack-name", toolkit_stack]

    # ---- 1. `cdk deploy --all --outputs-file` covers every stack this deploy touched -----------
    out1 = work / "out1.json"
    _cdk(ctx, work, ["deploy", "--all", "--outputs-file", str(out1), *deploy_flags],
         {"account": ctx.account, "region": ctx.region, "stack_a": stack_a, "stack_b": stack_b,
          "param_a": param_a, "param_b": param_b, "value_a": value_a1, "value_b": value_b1},
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    written1 = json.loads(out1.read_text())
    assert set(written1) == {stack_a, stack_b}, (
        f"outputs-file after `deploy --all` has keys {sorted(written1)}, expected exactly "
        f"[{stack_a!r}, {stack_b!r}]"
    )
    for stack, param, value in ((stack_a, param_a, value_a1), (stack_b, param_b, value_b1)):
        expected = _describe_outputs(cfn, stack)
        assert written1[stack] == expected, (
            f"outputs-file entry for {stack!r} is {written1[stack]!r}, expected it to match "
            f"DescribeStacks' own Outputs {expected!r}"
        )
        _assert_outputs_match_parameter(ssm, written1[stack], param, value)

    # ---- 2. Redeploying ONLY stack A writes a file covering A alone, with A's NEW value ---------
    out2 = work / "out2.json"
    _cdk(ctx, work, ["deploy", stack_a, "--outputs-file", str(out2), *deploy_flags],
         {"account": ctx.account, "region": ctx.region, "stack_a": stack_a, "stack_b": stack_b,
          "param_a": param_a, "param_b": param_b, "value_a": value_a2, "value_b": value_b1},
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    written2 = json.loads(out2.read_text())
    assert set(written2) == {stack_a}, (
        f"outputs-file after deploying only {stack_a!r} has keys {sorted(written2)}, expected "
        f"exactly [{stack_a!r}] — a stack not named in this deploy must not appear"
    )
    expected_a = _describe_outputs(cfn, stack_a)
    assert written2[stack_a] == expected_a, (
        f"outputs-file entry for {stack_a!r} is {written2[stack_a]!r}, expected it to match "
        f"DescribeStacks' own (updated) Outputs {expected_a!r}"
    )
    live_values = {o["OutputKey"]: o["OutputValue"] for o in
                   cfn.describe_stacks(StackName=stack_a)["Stacks"][0]["Outputs"]}
    assert live_values["ParamValue"] == value_a2, (
        f"stack {stack_a!r}'s live ParamValue output is {live_values['ParamValue']!r}, expected "
        f"the second deploy's updated value {value_a2!r}"
    )
    assert written2[stack_a]["ParamValue"] == value_a2, (
        f"outputs-file's ParamValue for {stack_a!r} is {written2[stack_a]['ParamValue']!r}, "
        f"expected the current value {value_a2!r} rather than the first deploy's {value_a1!r}"
    )
    _assert_outputs_match_parameter(ssm, written2[stack_a], param_a, value_a2)

    # stack B, untouched by step 2, must be unaffected and absent from written2 (already asserted).
    unchanged_b = {o["OutputKey"]: o["OutputValue"] for o in
                   cfn.describe_stacks(StackName=stack_b)["Stacks"][0]["Outputs"]}
    assert unchanged_b["ParamValue"] == value_b1, (
        f"stack {stack_b!r}'s ParamValue changed to {unchanged_b['ParamValue']!r} from a deploy "
        f"that never named it; expected it to still read {value_b1!r}"
    )
    _assert_outputs_match_parameter(ssm, unchanged_b, param_b, value_b1)


def _assert_outputs_match_parameter(ssm, outputs: dict[str, str], name: str, value: str) -> None:
    """The SSM parameter itself holds *value*, and its ARN and Value are the stack's outputs."""
    parameter = ssm.get_parameter(Name=name)["Parameter"]
    assert parameter["Value"] == value, (
        f"SSM parameter {name!r} holds {parameter['Value']!r}, expected {value!r} from the "
        f"latest deploy that named its stack"
    )
    assert outputs.get("ParamValue") == parameter["Value"], (
        f"output ParamValue {outputs.get('ParamValue')!r} differs from SSM parameter {name!r}'s "
        f"own Value {parameter['Value']!r}"
    )
    assert outputs.get("ParamArn") == parameter["ARN"], (
        f"output ParamArn {outputs.get('ParamArn')!r} differs from SSM parameter {name!r}'s "
        f"own ARN {parameter['ARN']!r}"
    )


def _describe_outputs(cfn, stack: str) -> dict[str, str]:
    """DescribeStacks' own OutputKey -> OutputValue mapping for *stack*."""
    outputs = cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


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
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`."""
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
    """Delete by StackId, then poll to DELETE_COMPLETE; raise on DELETE_FAILED or timeout."""
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
    """Delete every stack this check created; collect-then-raise so one failing delete never
    stops the rest from being attempted."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    for stack in stacks:
        try:
            _delete_stack_and_wait(ctx, stack, timeout_s=max(30.0, deadline - time.monotonic()))
        except Exception as exc:  # noqa: BLE001 — collected below, the loop's end always raises
            problems.append(f"stack {stack}: {exc!r}")
    if problems:
        raise AssertionError("teardown left residue: " + "; ".join(problems))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
