"""cdk-table-default-removal-policy-retains-past-destroy."""
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

CHECK = "cdk-table-default-removal-policy-retains-past-destroy"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 420.0
_TABLE_GONE_DEADLINE_S = 300.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_table_removal"


@tags("axis:happy-path", "cap:c2", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A `Table` with no `removal_policy` defaults to RETAIN, so `cdk destroy` leaves a live,
    billable table with its row still readable; its twin with `removal_policy=DESTROY` is gone and
    unusable. Only a target that reads the policy per-resource passes both arms.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    stack = ctx.unique_name("sim2real-cdkretain-")
    app_context = {"account": account, "region": ctx.region, "stack_name": stack}
    work = _stage_app(ctx, _APP)

    retained_table: str | None = None
    retained_marker = ctx.unique_name("retained-marker-")
    retained_key = ctx.unique_name("retained-key-")

    def _cleanup() -> None:
        # The whole point of the retained arm is that nothing else will ever clean this table up.
        after = [(f"delete retained table {retained_table}",
                  lambda: _delete_table_and_confirm(ctx, retained_table))] if retained_table else None
        _teardown(ctx, [stack], after=after)

    ctx.on_cleanup(_cleanup)

    # ---- the construct-level claim, asserted on the template BEFORE anything is deployed ----
    _, _, template = _synth_doc(ctx, work, stack, app_context, out="out-1",
                                timeout_s=_DEPLOY_TIMEOUT_S)
    tables = _resources_of_type(template, "AWS::DynamoDB::Table")
    assert len(tables) == 2, (
        f"the synthesised template holds {len(tables)} DynamoDB tables ({sorted(tables)!r}), "
        f"expected exactly 2 — the retained/destroyed contrast needs both"
    )
    policies = {
        logical_id: (resource.get("DeletionPolicy"), resource.get("UpdateReplacePolicy"))
        for logical_id, resource in tables.items()
    }
    retained_ids = [k for k, v in policies.items() if v == ("Retain", "Retain")]
    destroyed_ids = [k for k, v in policies.items() if v == ("Delete", "Delete")]
    assert len(retained_ids) == 1 and len(destroyed_ids) == 1, (
        f"expected exactly one Retain/Retain table and one Delete/Delete table, the template's "
        f"policies were {policies!r}. The default-props table must be Retain — that default is "
        f"this check's subject"
    )
    assert retained_ids[0].startswith("Retained"), (
        f"the Retain/Retain table's logical id is {retained_ids[0]!r}, expected the construct "
        f"named 'Retained' (the one built with NO removal_policy argument) — the contrast is "
        f"reversed from what this check asserts"
    )

    # ---- deploy, and seed BOTH tables so survival can be asserted on data ------------------
    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], app_context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    outputs = _stack_outputs(ctx, stack)
    stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    retained_table = outputs["RetainedTableName"]
    destroyed_table = outputs["DestroyedTableName"]
    assert retained_table != destroyed_table, (
        f"both outputs named the same table {retained_table!r}"
    )
    destroyed_key = ctx.unique_name("destroyed-key-")
    ddb.put_item(TableName=retained_table,
                 Item={"pk": {"S": retained_key}, "marker": {"S": retained_marker}})
    ddb.put_item(TableName=destroyed_table,
                 Item={"pk": {"S": destroyed_key}, "marker": {"S": ctx.unique_name("d-")}})
    for name in (retained_table, destroyed_table):
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        assert status == "ACTIVE", (
            f"table {name!r} is {status!r} after CREATE_COMPLETE, expected ACTIVE"
        )

    # ---- destroy -----------------------------------------------------------------------------
    _cdk(ctx, work, ["destroy", stack, "--force"], app_context,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)
    _assert_stack_absent(ctx, stack)

    # ---- TERMINAL READ: the retained table's ROW is still there -----------------------------
    survivor_status = ddb.describe_table(TableName=retained_table)["Table"]["TableStatus"]
    assert survivor_status == "ACTIVE", (
        f"the default-props (Retain) table {retained_table!r} is {survivor_status!r} after "
        f"`cdk destroy`, expected ACTIVE — DeletionPolicy: Retain was not honoured"
    )
    survivor_row = ddb.get_item(TableName=retained_table, Key={"pk": {"S": retained_key}},
                                ConsistentRead=True).get("Item")
    assert survivor_row is not None, (
        f"the retained table {retained_table!r} still exists but its row at pk="
        f"{retained_key!r} is gone — retaining a table that lost its contents is not retention"
    )
    assert survivor_row.get("marker", {}).get("S") == retained_marker, (
        f"the retained table's row carries marker "
        f"{survivor_row.get('marker', {}).get('S')!r}, expected {retained_marker!r}"
    )

    # ---- the twin: gone, and unusable -------------------------------------------------------
    describe_exc = _client_error(lambda: ddb.describe_table(TableName=destroyed_table))
    assert describe_exc.response["Error"]["Code"] == "ResourceNotFoundException", (
        f"DescribeTable on {destroyed_table!r} (removal_policy=DESTROY) did not report "
        f"ResourceNotFoundException after `cdk destroy` — a target that ignores DeletionPolicy "
        f"and deletes nothing passes the retained arm and fails here"
    )
    assert describe_exc.response["Error"]["Message"] == (
        f"Requested resource not found: Table: {destroyed_table} not found"
    ), (
        f"DescribeTable on the deleted table {destroyed_table!r} raised "
        f"ResourceNotFoundException with message "
        f"{describe_exc.response['Error'].get('Message')!r}"
    )
    put_exc = _client_error(
        lambda: ddb.put_item(TableName=destroyed_table,
                             Item={"pk": {"S": ctx.unique_name("zombie-")}})
    )
    assert put_exc.response["Error"]["Code"] == "ResourceNotFoundException", (
        f"PutItem on the deleted table {destroyed_table!r} did not report "
        f"ResourceNotFoundException — the id is gone from reads but still accepts mutations"
    )
    assert put_exc.response["Error"]["Message"] == "Requested resource not found", (
        f"PutItem on the deleted table {destroyed_table!r} raised ResourceNotFoundException "
        f"with message {put_exc.response['Error'].get('Message')!r}"
    )

    # ---- secondary: CloudFormation should have SAID it skipped the retained resource ---------
    # DescribeStackEvents by NAME fails with ValidationError ("does not exist") once the stack
    # is gone, exactly like DescribeStacks by name. The stack ID (ARN), captured before
    # destroy, is what CloudFormation keeps answering for.
    skipped = _deletion_skipped_logical_ids(cfn, stack_id)
    assert skipped == {retained_ids[0]}, (
        f"stack events for the delete report DELETE_SKIPPED for {sorted(skipped)!r}, expected "
        f"exactly the retained table's logical id {retained_ids[0]!r} — the resource survived, "
        f"so CloudFormation must have recorded skipping it, and nothing else"
    )


# ===== helpers =====


def _deletion_skipped_logical_ids(cfn, stack_id: str) -> set[str]:
    """Logical ids CloudFormation reported as DELETE_SKIPPED while deleting the stack identified by
    *stack_id*.

    Addressed by the stack's ID (ARN): by name, DescribeStackEvents refuses a deleted stack.
    """
    skipped: set[str] = set()
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for event in page["StackEvents"]:
            if event.get("ResourceStatus") == "DELETE_SKIPPED":
                skipped.add(event["LogicalResourceId"])
    return skipped


def _delete_table_and_confirm(ctx, table_name: str) -> None:
    """Delete the retained table and poll until an independent read says it is gone.

    Raises on timeout, so a survivor this check created can never be silently left running.
    """
    ddb = ctx.client("dynamodb")
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + _TABLE_GONE_DEADLINE_S
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(5.0)
    raise AssertionError(
        f"the retained table {table_name!r} did not disappear within {_TABLE_GONE_DEADLINE_S}s of "
        f"DeleteTable (last status {last!r}) — it is leaking"
    )


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo.

    The app must EXIST on disk; this asserts rather than creating anything.
    """
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
               timeout_s: float) -> tuple[int, str, dict[str, Any]]:
    """Synthesise into `<work>/<out>`, asserting exit 0; return `(rc, output, parsed template)`."""
    shutil.rmtree(work / out, ignore_errors=True)
    rc, output = _cdk(ctx, work, ["synth", stack, "--output", out, "--quiet"], context,
                      timeout_s=timeout_s, expect_rc=0)
    template = work / out / f"{stack}.template.json"
    assert template.is_file(), (
        f"`cdk synth` exited {rc} but wrote no template at {template}; {out} contains "
        f"{sorted(p.name for p in (work / out).iterdir()) if (work / out).is_dir() else 'nothing'}"
    )
    return rc, output, json.loads(template.read_text())


def _resources_of_type(template: dict[str, Any], type_name: str) -> dict[str, Any]:
    """Every resource of *type_name*, keyed by logical id. Hard-subscripts `Resources` on purpose."""
    return {k: v for k, v in template["Resources"].items() if v["Type"] == type_name}


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's outputs file.

    Deliberately an independent read: `--outputs-file` is written by the same process that did the
    deploy, so believing it would make the CLI both actor and witness.
    """
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


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


def _assert_stack_absent(ctx, stack: str) -> None:
    """An independent read must report the stack gone with CloudFormation's specific code."""
    exc = _client_error(lambda: ctx.client("cloudformation").describe_stacks(StackName=stack))
    code = exc.response["Error"]["Code"]
    assert code == "ValidationError", (
        f"DescribeStacks on the deleted stack {stack!r} returned error code {code!r}, expected "
        f"'ValidationError'"
    )
    assert exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        f"DescribeStacks on the deleted stack {stack!r} raised ValidationError with message "
        f"{exc.response['Error'].get('Message')!r}, expected 'Stack with id {stack} does not exist'"
    )


def _teardown(ctx, stacks: list[str], after: list[tuple[str, Any]] | None = None) -> None:
    """Delete each stack this run created, then run each after step; raise every failure."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps = [
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
