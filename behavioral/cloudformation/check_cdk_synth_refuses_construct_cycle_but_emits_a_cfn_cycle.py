"""cdk-synth-refuses-construct-cycle-but-emits-a-cfn-cycle."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-synth-refuses-construct-cycle-but-emits-a-cfn-cycle"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 420.0
_SYNTH_TIMEOUT_S = 240.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_cycle"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CDK refuses a construct-graph cycle at synth without writing a template, yet emits a
    Fn::GetAtt cycle that CreateStack refuses with ValidationError; the acyclic app works.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    prefix = ctx.unique_name("sim2real-cdkcyc-")
    data_stack, compute_stack = f"{prefix}-data", f"{prefix}-compute"
    cycle_stack = ctx.unique_name("sim2real-cdkcyc-tmpl-")
    base = {"account": account, "region": ctx.region}
    work = _stage_app(ctx, _APP)
    fn_name: str | None = None

    def _cleanup() -> None:
        # The invoke makes Lambda create this log group; CloudFormation never adopted it and does
        # not delete it when the stack goes, so it is reaped after the stacks.
        after = [("log group", lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))] \
            if fn_name else None
        # `compute_stack` first: it holds the cross-stack reference, so CloudFormation refuses to
        # delete `data_stack` while its export is still imported.
        _teardown(ctx, [compute_stack, data_stack, cycle_stack], after=after)

    ctx.on_cleanup(_cleanup)

    # ---- 1. CDK's own refusal, before any template exists -----------------------------------
    cyclic_context = {**base, "stack_name": prefix, "mode": "construct-cycle"}
    shutil.rmtree(work / "out-cycle", ignore_errors=True)
    rc, output = _cdk(ctx, work, ["synth", "--output", "out-cycle"], cyclic_context,
                      timeout_s=_SYNTH_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk synth` exited {rc} for the construct-cycle app, expected 1; CDK must refuse a "
        f"cyclic reference between two stacks. Output tail: {output[-800:]!r}"
    )
    # The error class name varies across aws-cdk-lib releases, so assert on the message.
    assert f"'{data_stack}' depends on '{compute_stack}'" in output, (
        f"`cdk synth` failed but does not name the {data_stack} -> {compute_stack} dependency, "
        f"so the failure is not the cycle; output tail: {output[-1000:]!r}"
    )
    assert "would create a cyclic reference" in output, (
        f"the refusal does not carry CDK's documented explanation 'would create a cyclic "
        f"reference'; output tail: {output[-1000:]!r}"
    )
    emitted = sorted((work / "out-cycle").glob("*.template.json")) \
        if (work / "out-cycle").is_dir() else []
    assert emitted == [], (
        f"the refused synth still wrote templates {[p.name for p in emitted]!r}; a refusal must "
        f"leave no usable assembly behind"
    )

    # ---- 2. the cycle CDK is HAPPY to emit, which only the target can refuse ------------------
    template_context = {**base, "stack_name": cycle_stack, "mode": "template-cycle"}
    _, _, cycle_template = _synth_doc(ctx, work, cycle_stack, template_context, out="out-tmpl",
                                      timeout_s=_SYNTH_TIMEOUT_S, expect_rc=0)
    assert cycle_template is not None, (
        "`cdk synth` exited 0 for the template-cycle app but produced no template"
    )
    parameters = _resources_of_type(cycle_template, "AWS::SSM::Parameter")
    assert len(parameters) == 2, (
        f"the template-cycle app synthesised {len(parameters)} SSM parameters "
        f"({sorted(parameters)!r}), expected exactly 2"
    )
    referenced = {
        logical_id: resource["Properties"]["Value"]["Fn::GetAtt"][0]
        for logical_id, resource in parameters.items()
    }
    assert referenced == {"Left": "Right", "Right": "Left"}, (
        f"the two synthesised parameters do not reference each other: {referenced!r}, expected "
        f"{{'Left': 'Right', 'Right': 'Left'}} — CDK did not emit the cycle this arm depends on, "
        f"so the target is never asked the question"
    )
    refusal = _create_stack_and_expect_refusal(ctx, cycle_stack, json.dumps(cycle_template))
    assert refusal == ("ValidationError", "Circular dependency between resources: [Left, Right]"), (
        f"CreateStack refused the cyclic template with {refusal!r}"
    )
    # Effect-absent: the refused CreateStack left no stack behind.
    absent = _client_error(
        lambda: ctx.client("cloudformation").describe_stacks(StackName=cycle_stack))
    assert (absent.response["Error"]["Code"], absent.response["Error"]["Message"]) == (
        "ValidationError", f"Stack with id {cycle_stack} does not exist"), (
        f"DescribeStacks on the refused stack {cycle_stack!r} raised "
        f"{absent.response['Error']!r}, expected the stack to be absent"
    )

    # ---- 3. RESTORE: the same constructs, one reference removed, deployed and working ---------
    valid_context = {**base, "stack_name": prefix, "mode": "valid"}
    _cdk(ctx, work, ["deploy", "--all", "--require-approval", "never"], valid_context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    table_name = _stack_outputs(ctx, data_stack)["TableName"]
    fn_name = _stack_outputs(ctx, compute_stack)["FunctionName"]
    key = ctx.unique_name("key-")
    marker = ctx.unique_name("marker-")
    wrote = _invoke(lam, fn_name, {"key": key, "marker": marker})
    assert wrote == {"wrote": key, "table": table_name}, (
        f"invoking the cross-stack function {fn_name!r} returned {wrote!r}, expected "
        f"{{'wrote': {key!r}, 'table': {table_name!r}}} — the Compute stack's function is not "
        f"pointed at the Data stack's table"
    )
    # TERMINAL READ: at the consumer of the cross-stack reference, via a different operation.
    row = ddb.get_item(TableName=table_name, Key={"pk": {"S": key}},
                       ConsistentRead=True).get("Item")
    assert row is not None and row.get("marker", {}).get("S") == marker, (
        f"GetItem on {table_name!r} at pk={key!r} returned {row!r}, expected marker {marker!r} — "
        f"the acyclic cross-stack reference did not produce a working pair of stacks, so the two "
        f"refusals above cannot be attributed to the cycles"
    )


# ===== helpers =====


def _create_stack_and_expect_refusal(ctx, stack: str, template_body: str) -> tuple[str, str]:
    """Create the stack and require a synchronous refusal, returning `(code, message)`."""
    cfn = ctx.client("cloudformation")
    try:
        # A stack the target accepts is left in place for the check's teardown to delete.
        cfn.create_stack(StackName=stack, TemplateBody=template_body,
                         OnFailure="DO_NOTHING",
                         Tags=[{"Key": "sim2real", "Value": "cdk-cycle-check"}])
    except ClientError as exc:
        error = exc.response["Error"]
        return str(error.get("Code")), str(error.get("Message", ""))

    raise AssertionError(
        f"CreateStack accepted the cyclic template for stack {stack!r}; CloudFormation refuses a "
        f"Fn::GetAtt cycle synchronously with ValidationError"
    )


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


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
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`.

    `--no-version-reporting` drops the `AWS::CDK::Metadata` resource and CLI telemetry;
    `--no-color` keeps ANSI escapes out of any asserted output; `--ci` sends logs to stdout.
    """
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output tail: "
            f"{output[-1200:]!r}"
        )
    return result.returncode, output


def _synth_doc(ctx, work: Path, stack: str, context: dict[str, str], *, out: str,
               timeout_s: float, expect_rc: int = 0) -> tuple[int, str, dict[str, Any] | None]:
    """Synthesise into `<work>/<out>`; return `(rc, output, parsed template or None)`.

    The template is None only when synth failed; the caller decides what that means.
    """
    shutil.rmtree(work / out, ignore_errors=True)
    rc, output = _cdk(ctx, work, ["synth", stack, "--output", out, "--quiet"], context,
                      timeout_s=timeout_s, expect_rc=expect_rc)
    template = work / out / f"{stack}.template.json"
    if rc != 0 and not template.is_file():
        return rc, output, None
    assert template.is_file(), (
        f"`cdk synth` exited {rc} but wrote no template at {template}; {out} contains "
        f"{sorted(p.name for p in (work / out).iterdir()) if (work / out).is_dir() else 'nothing'}"
    )
    return rc, output, json.loads(template.read_text())


def _resources_of_type(template: dict[str, Any], type_name: str) -> dict[str, Any]:
    """Every resource of *type_name*, keyed by logical id."""
    return {k: v for k, v in template["Resources"].items() if v["Type"] == type_name}


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's outputs file."""
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _invoke(lam, fn_name: str, event: dict[str, Any]) -> Any:
    """Invoke and decode, treating a handler error as a failure rather than a payload."""
    response = lam.invoke(FunctionName=fn_name, Payload=json.dumps(event).encode())
    body = response["Payload"].read()
    assert "FunctionError" not in response, (
        f"invoking {fn_name!r} raised {response.get('FunctionError')!r}: {body[:400]!r}"
    )
    return json.loads(body)


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group *name* until *reads* consecutive reads find it absent; raise on budget."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(f"log group {name!r} still present after {budget_s}s of deletes")
        time.sleep(interval_s)


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist":
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
        # Bounded: CloudFormation deletes are asynchronous with no notification channel.
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _teardown(ctx, stacks: list[str], extra: list[tuple[str, Any]] | None = None,
              after: list[tuple[str, Any]] | None = None) -> None:
    """Run each extra, delete each stack this run created, then each after; raise every failure."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps = list(extra or [])
    steps += [
        (f"stack {stack}", lambda s=stack: _delete_stack_and_wait(
            ctx, s, timeout_s=max(30.0, deadline - time.monotonic())))
        for stack in stacks
    ]
    steps += list(after or [])
    for label, fn in steps:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - every step runs; the failures are raised below
            problems.append(f"{label}: {exc!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
