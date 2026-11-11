"""deploy-cdk-cross-stack-export-ordering-and-in-use-guard."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-cross-stack-export-ordering-and-in-use-guard"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_DEPLOY_ALL_TIMEOUT_S = 600.0
_DEPLOY_ONE_TIMEOUT_S = 300.0
_DESTROY_TIMEOUT_S = 300.0
_IMPORT_REGISTER_TIMEOUT_S = 180.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_cross_stack_export"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """`cdk deploy --all` orders a stack ahead of the one importing its automatic cross-stack
    export; changing or deleting only the exporting stack while the import stands is refused with
    CloudFormation's own message, leaving the old value in place; `cdk destroy --all` reverses it.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    prefix = ctx.unique_name("sim2real-cdkexp-")
    producer_stack = f"{prefix}-producer"
    consumer_stack = f"{prefix}-consumer"
    # Never created: `cdk deploy` reads this name instead of the account's default toolkit stack.
    toolkit_stack = f"{prefix}-toolkit"
    producer_param = ctx.unique_name("sim2real-cdkexp-producer-")
    consumer_param = ctx.unique_name("sim2real-cdkexp-consumer-")
    value_v1 = ctx.unique_name("v1-")
    value_v2 = ctx.unique_name("v2-")
    description_v1 = ctx.unique_name("d1-")
    description_v2 = ctx.unique_name("d2-")

    base_context = {
        "account": ctx.account, "region": ctx.region, "stack_prefix": prefix,
        "producer_param_name": producer_param, "consumer_param_name": consumer_param,
    }
    deploy_flags = ["--require-approval", "never", "--toolkit-stack-name", toolkit_stack]
    work = _stage_app(ctx, _APP)
    ctx.on_cleanup(lambda: _teardown(ctx, [consumer_stack, producer_stack]))

    # ---- 1. `cdk deploy --all` creates Producer, then Consumer, which imports its export --------
    _cdk(ctx, work, ["deploy", "--all", *deploy_flags],
         {**base_context, "producer_value": value_v1, "producer_description": description_v1},
         timeout_s=_DEPLOY_ALL_TIMEOUT_S, expect_rc=0)

    # StackId (ARN) rather than name: a name stops resolving in DescribeStackEvents once the
    # stack is fully deleted, while the ARN keeps working for the ordering checks after step 5.
    producer_id = cfn.describe_stacks(StackName=producer_stack)["Stacks"][0]["StackId"]
    consumer_id = cfn.describe_stacks(StackName=consumer_stack)["Stacks"][0]["StackId"]

    producer_done_at = _stack_level_event_time(cfn, producer_id, "CREATE_COMPLETE")
    consumer_started_at = cfn.describe_stacks(StackName=consumer_id)["Stacks"][0]["CreationTime"]
    assert producer_done_at <= consumer_started_at, (
        f"Producer {producer_stack!r} reached CREATE_COMPLETE at {producer_done_at!r}, after "
        f"Consumer {consumer_stack!r} started being created at {consumer_started_at!r}; "
        f"`cdk deploy --all` must finish the exporting stack before starting the importing one"
    )

    exported_value = ssm.get_parameter(Name=producer_param)["Parameter"]["Value"]
    assert exported_value == value_v1, (
        f"Producer's own parameter {producer_param!r} holds {exported_value!r}, expected the "
        f"value this deploy set, {value_v1!r}"
    )
    imported_value = ssm.get_parameter(Name=consumer_param)["Parameter"]["Value"]
    assert imported_value == value_v1, (
        f"Consumer's parameter {consumer_param!r} holds {imported_value!r}, expected "
        f"{value_v1!r} carried in through the automatic cross-stack export/import"
    )

    export_name = _export_name(cfn, producer_id)
    _await_import_registered(cfn, export_name, consumer_stack)

    # ---- 2. POSITIVE CONTROL: updating Producer without touching the exported value succeeds -----
    _cdk(ctx, work, ["deploy", producer_stack, *deploy_flags],
         {**base_context, "producer_value": value_v1, "producer_description": description_v2},
         timeout_s=_DEPLOY_ONE_TIMEOUT_S, expect_rc=0)
    control_description = _parameter_description(ssm, producer_param)
    assert control_description == description_v2, (
        f"positive control: Producer's parameter Description is {control_description!r}, expected "
        f"the control update's {description_v2!r} — a deploy touching only the non-exported "
        f"property must still reach UPDATE_COMPLETE"
    )
    control_value = ssm.get_parameter(Name=producer_param)["Parameter"]["Value"]
    assert control_value == value_v1, (
        f"positive control: Producer's parameter Value changed to {control_value!r}; it was never "
        f"touched by the control update and should still read {value_v1!r}"
    )

    # ---- 3. NEGATIVE: changing the exported value while Consumer imports it is refused -----------
    attempted_context = {
        **base_context, "producer_value": value_v2, "producer_description": description_v2,
    }
    rc, _ = _cdk(ctx, work, ["deploy", producer_stack, *deploy_flags],
                attempted_context, timeout_s=_DEPLOY_ONE_TIMEOUT_S, expect_rc=None)
    assert rc != 0, (
        f"`cdk deploy {producer_stack}` exited 0 while changing the exported parameter Value from "
        f"{value_v1!r} to {value_v2!r}; {consumer_stack!r} still imports the export, so "
        f"CloudFormation must refuse this update"
    )
    update_reason = _latest_reason(cfn, producer_id)
    expected_update_reason = (
        f"Update canceled. Cannot update export {export_name} as it is in use by {consumer_stack}."
    )
    assert update_reason == expected_update_reason, (
        f"Producer's refusal reason was {update_reason!r}, expected {expected_update_reason!r}"
    )
    still_value = ssm.get_parameter(Name=producer_param)["Parameter"]["Value"]
    assert still_value == value_v1, (
        f"after the refused update, Producer's parameter Value is {still_value!r}; it must still "
        f"hold the pre-update value {value_v1!r}"
    )
    still_imported = ssm.get_parameter(Name=consumer_param)["Parameter"]["Value"]
    assert still_imported == value_v1, (
        f"after the refused update, Consumer's parameter Value is {still_imported!r}; the import "
        f"must still read the unchanged export {value_v1!r}"
    )

    # ---- 4. NEGATIVE: deleting the exporting stack while Consumer imports it is refused -----------
    # `--exclusively` keeps this to the Producer stack alone; without it `cdk destroy` pulls in
    # every dependent stack (Consumer included), which would remove the very import under test.
    rc, _ = _cdk(ctx, work, ["destroy", producer_stack, "--exclusively", "--force"],
                attempted_context, timeout_s=_DESTROY_TIMEOUT_S, expect_rc=None)
    assert rc != 0, (
        f"`cdk destroy {producer_stack}` exited 0 while {consumer_stack!r} still imports its "
        f"export {export_name!r}; CloudFormation must refuse to delete it"
    )
    assert not _stack_absent(cfn, producer_id), (
        f"Producer {producer_stack!r} no longer exists after a delete that should have been "
        f"refused while {consumer_stack!r} still imports its export"
    )
    delete_reason = _latest_reason(cfn, producer_id)
    expected_delete_reason = (
        f"Delete canceled. Cannot delete export {export_name} as it is in use by {consumer_stack}."
    )
    assert delete_reason == expected_delete_reason, (
        f"Producer's delete-refusal reason was {delete_reason!r}, expected "
        f"{expected_delete_reason!r}"
    )
    surviving_value = ssm.get_parameter(Name=producer_param)["Parameter"]["Value"]
    assert surviving_value == value_v1, (
        f"after the refused delete, Producer's parameter Value is {surviving_value!r}, expected "
        f"the surviving resource to still read {value_v1!r}"
    )

    # ---- 5. `cdk destroy --all` deletes Consumer, then Producer, in that order --------------------
    _cdk(ctx, work, ["destroy", "--all", "--force"], attempted_context,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)

    consumer_gone_at = _stack_level_event_time(cfn, consumer_id, "DELETE_COMPLETE")
    producer_delete_started_at = _stack_level_event_time(cfn, producer_id, "DELETE_IN_PROGRESS")
    assert consumer_gone_at <= producer_delete_started_at, (
        f"Consumer {consumer_stack!r} reached DELETE_COMPLETE at {consumer_gone_at!r}, after "
        f"Producer {producer_stack!r} started its final delete at {producer_delete_started_at!r}; "
        f"`cdk destroy --all` must delete the importing stack before the exporting one"
    )
    assert _stack_absent(cfn, producer_id), f"Producer {producer_stack!r} still exists"
    assert _stack_absent(cfn, consumer_id), f"Consumer {consumer_stack!r} still exists"
    gone_producer = _client_error(lambda: ssm.get_parameter(Name=producer_param))
    assert gone_producer.response["Error"]["Code"] == "ParameterNotFound", (
        f"Producer's parameter {producer_param!r} is still readable after `cdk destroy --all`: "
        f"{gone_producer.response['Error']!r}"
    )
    assert gone_producer.response["Error"]["Message"] == "", gone_producer.response["Error"]
    gone_consumer = _client_error(lambda: ssm.get_parameter(Name=consumer_param))
    assert gone_consumer.response["Error"]["Code"] == "ParameterNotFound", (
        f"Consumer's parameter {consumer_param!r} is still readable after `cdk destroy --all`: "
        f"{gone_consumer.response['Error']!r}"
    )
    assert gone_consumer.response["Error"]["Message"] == "", gone_consumer.response["Error"]


def _parameter_description(ssm, name: str) -> str:
    """The parameter's Description, which GetParameter does not return."""
    params = ssm.describe_parameters(
        ParameterFilters=[{"Key": "Name", "Values": [name]}]
    )["Parameters"]
    assert len(params) == 1, f"DescribeParameters({name!r}) returned {len(params)} parameters"
    return str(params[0].get("Description", ""))


def _client_error(fn) -> ClientError:
    """The ClientError ``fn`` raises, for when the MESSAGE matters as well as the code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
    `--no-notices` keeps the CLI off its public notices feed; `--no-color` keeps ANSI escapes out
    of any asserted output; `--ci` sends logs to stdout.
    """
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
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


def _export_name(cfn, stack: str) -> str:
    """The sole auto-generated Export name on *stack*'s sole Output."""
    outputs = cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    assert len(outputs) == 1, (
        f"stack {stack!r} has {len(outputs)} Outputs, expected exactly 1 (the automatic export)"
    )
    name = outputs[0].get("ExportName")
    assert name, f"stack {stack!r}'s sole Output carries no ExportName: {outputs[0]!r}"
    return str(name)


def _imports(cfn, export_name: str) -> list[str]:
    """Stacks importing ``export_name``; ListImports' ValidationError on empty means ``[]``."""
    try:
        return list(cfn.list_imports(ExportName=export_name)["Imports"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ValidationError":
            return []
        raise


def _await_import_registered(cfn, export_name: str, importer: str) -> None:
    """The cross-stack import index updates asynchronously relative to CREATE_COMPLETE."""
    deadline = time.monotonic() + _IMPORT_REGISTER_TIMEOUT_S
    last: list[str] = []
    while time.monotonic() < deadline:
        last = _imports(cfn, export_name)
        if importer in last:
            return
        time.sleep(4.0)
    raise AssertionError(
        f"ListImports({export_name!r}) never listed {importer!r} within "
        f"{_IMPORT_REGISTER_TIMEOUT_S}s (last={last!r})"
    )


def _stack_level_event_time(cfn, stack: str, status: str):
    """The Timestamp of the newest stack-level (AWS::CloudFormation::Stack) event at *status*.

    `stack` scopes `DescribeStackEvents` to one stack's own events, so every event already
    belongs to it; the resource-level filter alone picks out the stack (not a member resource).
    """
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        for event in page["StackEvents"]:
            if (event.get("ResourceType") == "AWS::CloudFormation::Stack"
                    and event.get("ResourceStatus") == status):
                return event["Timestamp"]
    raise AssertionError(f"no stack-level event at status {status!r} found for {stack!r}")


def _latest_reason(cfn, stack: str) -> str:
    """The most recent stack-level ResourceStatusReason, which carries the refusal message."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        for event in page["StackEvents"]:
            if event.get("ResourceType") == "AWS::CloudFormation::Stack":
                reason = event.get("ResourceStatusReason") or ""
                if reason:
                    return reason
    raise AssertionError(f"no stack-level event with a ResourceStatusReason found for {stack!r}")


def _is_stack_not_found(exc: ClientError) -> bool:
    """DescribeStacks' own not-found: a ValidationError saying the stack does not exist."""
    error = exc.response.get("Error", {})
    return (error.get("Code") == "ValidationError"
            and "does not exist" in str(error.get("Message", "")))


def _stack_absent(cfn, stack: str) -> bool:
    """True when *stack* is not found or is DELETE_COMPLETE; any other error raises."""
    try:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if _is_stack_not_found(exc):
            return True
        raise
    return status == "DELETE_COMPLETE"


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
    """Delete every stack this check created, consumer first; collect-then-raise so one failing
    delete never stops the rest from being attempted."""
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
