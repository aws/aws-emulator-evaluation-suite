"""cdk-grant-read-data-permits-real-read-denies-real-write."""
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

CHECK = "cdk-grant-read-data-permits-real-read-denies-real-write"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_DEPLOY_TIMEOUT_S = 600.0
# IAM propagation into a Lambda execution environment can take minutes in each direction.
_PROPAGATION_DEADLINE_S = 600.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_grant"
_REPAIR_POLICY_NAME = "sim2real-grant-repair"

#: The actions `grant_read_data` writes to the role's DefaultPolicy (table and stream reads).
_READ_ACTIONS = frozenset({
    "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:GetItem", "dynamodb:Scan",
    "dynamodb:ConditionCheckItem", "dynamodb:DescribeTable", "dynamodb:GetRecords",
    "dynamodb:GetShardIterator",
})
#: The actions `grant_read_write_data` adds to that set.
_WRITE_ACTIONS = frozenset({
    "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem",
})


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A function granted `grant_read_data` can GetItem but its PutItem is AccessDenied, while its
    ReadWrite twin can do both; adding then removing an inline PutItem policy flips the write
    allowed and back to denied, and the deployed policies hold the documented action sets.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    caller = ctx.client("sts").get_caller_identity()
    account = caller["Account"]
    # The partition comes from the caller's own ARN, never from a literal.
    partition = caller["Arn"].split(":")[1]
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-cdkgrant-")
    app_context = {"account": account, "region": ctx.region, "stack_name": stack}
    work = _stage_app(ctx, _APP)

    read_only_role: str | None = None
    invoked_functions: list[str] = []
    repair_attached = False

    def _cleanup() -> None:
        extra: list[tuple[str, Any]] = []
        if repair_attached and read_only_role:
            extra.append((
                f"delete inline policy {_REPAIR_POLICY_NAME} from {read_only_role}",
                lambda: iam.delete_role_policy(RoleName=read_only_role,
                                               PolicyName=_REPAIR_POLICY_NAME),
            ))
        # The function L2 does not own its log group, so the stack delete leaves it behind.
        after = [
            (f"log group for invoked function {fn_name}",
             lambda fn_name=fn_name: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))
            for fn_name in invoked_functions
        ]
        _teardown(ctx, [stack], extra, after)

    ctx.on_cleanup(_cleanup)

    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], app_context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = _stack_outputs(ctx, stack)
    for key in ("TableName", "TableArn", "ReadOnlyFunctionName", "ReadOnlyRoleName",
                "ReadWriteFunctionName", "ReadWriteRoleName"):
        assert key in outputs, (
            f"the deployed stack's Outputs are {sorted(outputs)!r}, expected {key!r}"
        )
    table_name = outputs["TableName"]
    table_arn = outputs["TableArn"]
    read_only_fn = outputs["ReadOnlyFunctionName"]
    read_only_role = outputs["ReadOnlyRoleName"]
    read_write_fn = outputs["ReadWriteFunctionName"]
    invoked_functions.extend([read_only_fn, read_write_fn])

    seeded_key = ctx.unique_name("seeded-")
    seeded_marker = ctx.unique_name("seed-marker-")
    ddb.put_item(TableName=table_name,
                 Item={"pk": {"S": seeded_key}, "marker": {"S": seeded_marker}})

    denied_key = ctx.unique_name("denied-")
    attempt = _invoke(lam, read_only_fn, {
        "read_key": seeded_key,
        "write_key": denied_key,
        "marker": ctx.unique_name("denied-marker-"),
    })
    read_outcome, write_outcome = attempt["read"], attempt["write"]
    assert read_outcome["ok"] is True, (
        f"the read-only function's own GetItem FAILED: {read_outcome!r}. grant_read_data must "
        f"permit reads; without that, the refusal below would only show the function cannot "
        f"reach DynamoDB at all"
    )
    assert read_outcome["value"] == seeded_marker, (
        f"the read-only function read {read_outcome['value']!r} at pk={seeded_key!r}, expected "
        f"the marker this check seeded, {seeded_marker!r}"
    )
    assert write_outcome["ok"] is False, (
        f"the read-only function's PutItem SUCCEEDED: {write_outcome!r}. grant_read_data confers "
        f"no write action, and over-permissiveness is exactly what this arm exists to catch"
    )
    assert write_outcome["code"] == "AccessDeniedException", (
        f"the denied PutItem returned error code {write_outcome['code']!r}, expected "
        f"'AccessDeniedException'; message {write_outcome.get('message', '')[:200]!r}"
    )
    expected_denial = _expected_put_item_denial(
        partition, account, read_only_role, read_only_fn, table_arn)
    assert write_outcome.get("message", "") == expected_denial, (
        f"the refusal message is {write_outcome.get('message', '')!r}, expected the "
        f"identity-policy denial of dynamodb:PutItem by {read_only_role!r} on {table_arn!r}: "
        f"{expected_denial!r}"
    )

    leaked = ddb.get_item(TableName=table_name, Key={"pk": {"S": denied_key}},
                          ConsistentRead=True).get("Item")
    assert leaked is None, (
        f"the denied PutItem still landed: GetItem at pk={denied_key!r} returned {leaked!r}, "
        f"expected nothing"
    )

    twin_key = ctx.unique_name("twin-")
    twin_marker = ctx.unique_name("twin-marker-")
    twin = _invoke(lam, read_write_fn, {
        "read_key": seeded_key, "write_key": twin_key, "marker": twin_marker,
    })
    assert twin["read"]["ok"] is True and twin["write"]["ok"] is True, (
        f"the ReadWrite twin reported {twin!r}; both calls must succeed. Without this control, "
        f"the deny above cannot be told from 'no Lambda can write to this table'"
    )
    twin_row = ddb.get_item(TableName=table_name, Key={"pk": {"S": twin_key}},
                            ConsistentRead=True).get("Item")
    assert twin_row is not None and twin_row.get("marker", {}).get("S") == twin_marker, (
        f"the ReadWrite twin reported its PutItem succeeded but GetItem at pk={twin_key!r} "
        f"returned {twin_row!r}, expected marker {twin_marker!r}"
    )

    read_only_actions = _granted_actions(iam, read_only_role)
    assert read_only_actions == _READ_ACTIONS, (
        f"the read-only role's deployed inline policies grant {sorted(read_only_actions)!r}, "
        f"expected exactly grant_read_data's action set {sorted(_READ_ACTIONS)!r}"
    )
    read_write_actions = _granted_actions(iam, outputs["ReadWriteRoleName"])
    assert read_write_actions == _READ_ACTIONS | _WRITE_ACTIONS, (
        f"the ReadWrite role's deployed inline policies grant {sorted(read_write_actions)!r}, "
        f"expected exactly grant_read_write_data's action set "
        f"{sorted(_READ_ACTIONS | _WRITE_ACTIONS)!r}"
    )

    iam.put_role_policy(
        RoleName=read_only_role,
        PolicyName=_REPAIR_POLICY_NAME,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem",
                           "Resource": table_arn}],
        }),
    )
    repair_attached = True
    repaired_key = ctx.unique_name("repaired-")
    repaired_marker = ctx.unique_name("repaired-marker-")

    def _attempt_write() -> dict[str, Any]:
        return _invoke(lam, read_only_fn, {
            "read_key": seeded_key, "write_key": repaired_key, "marker": repaired_marker,
        })["write"]

    _poll_until(
        _attempt_write, lambda outcome: outcome["ok"] is True,
        deadline_s=_PROPAGATION_DEADLINE_S,
        reason=(f"the {_REPAIR_POLICY_NAME!r} inline policy to reach the execution environment "
                f"of {read_only_fn!r} — an IAM policy change propagates asynchronously; each "
                f"attempt re-invokes so a fresh environment is used"),
        interval_s=10.0,
    )
    repaired_row = ddb.get_item(TableName=table_name, Key={"pk": {"S": repaired_key}},
                                ConsistentRead=True).get("Item")
    assert repaired_row is not None, (
        f"the read-only function reported its PutItem succeeded after the repair, but GetItem at "
        f"pk={repaired_key!r} found nothing — the reported success was not a write"
    )
    assert repaired_row.get("marker", {}).get("S") == repaired_marker, (
        f"the repaired write's row carries marker "
        f"{repaired_row.get('marker', {}).get('S')!r}, expected {repaired_marker!r}"
    )

    iam.delete_role_policy(RoleName=read_only_role, PolicyName=_REPAIR_POLICY_NAME)
    repair_attached = False

    # A fresh key per attempt: attempts made before the revoke propagates really write, so
    # absence is asserted only for the key of the final, denied attempt.
    revoke_attempt_keys: list[str] = []

    def _attempt_after_revoke() -> dict[str, Any]:
        key = ctx.unique_name("revoked-")
        revoke_attempt_keys.append(key)
        return _invoke(lam, read_only_fn, {
            "read_key": seeded_key, "write_key": key,
            "marker": ctx.unique_name("revoked-marker-"),
        })["write"]

    final = _poll_until(
        _attempt_after_revoke,
        lambda outcome: outcome["ok"] is False,
        deadline_s=_PROPAGATION_DEADLINE_S,
        reason=(f"the removal of {_REPAIR_POLICY_NAME!r} to take effect for {read_only_fn!r} — "
                f"without this leg the repair above could be a one-way door that any target "
                f"passes by simply never denying again"),
        interval_s=10.0,
    )
    revoked_key = revoke_attempt_keys[-1]
    assert final["code"] == "AccessDeniedException", (
        f"after the repair policy was deleted, the write failed with code {final['code']!r}, "
        f"expected 'AccessDeniedException'; message {final.get('message', '')[:200]!r}"
    )
    assert final.get("message", "") == expected_denial, (
        f"after the repair policy was deleted, the refusal message is "
        f"{final.get('message', '')!r}, expected the same identity-policy denial as before the "
        f"repair: {expected_denial!r}"
    )
    assert ddb.get_item(TableName=table_name, Key={"pk": {"S": revoked_key}},
                        ConsistentRead=True).get("Item") is None, (
        f"the post-revocation write still landed a row at pk={revoked_key!r}"
    )


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


def _granted_actions(iam, role_name: str) -> set[str]:
    """Every Allow action in every inline policy on *role_name*, read back from IAM.

    Inline only, because CDK's `grant*` methods write to the role's inline `DefaultPolicy`.
    """
    actions: set[str] = set()
    for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
        for policy_name in page["PolicyNames"]:
            document = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)[
                "PolicyDocument"]
            for statement in document["Statement"]:
                if statement.get("Effect") != "Allow":
                    continue
                declared = statement["Action"]
                actions.update([declared] if isinstance(declared, str) else declared)
    return actions


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


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's outputs file."""
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


#: The length the deployed handler truncates every ClientError message to (see its `[:400]`).
_HANDLER_MESSAGE_LIMIT = 400


def _expected_put_item_denial(partition: str, account: str, role_name: str, function_name: str,
                              table_arn: str) -> str:
    """The exact message DynamoDB returns for a PutItem no identity-based policy allows, truncated
    the same way the deployed handler truncates it. Lambda assumes its execution role with a
    session name equal to the function's own name, so *function_name* names that session.
    """
    full = (
        f"User: arn:{partition}:sts::{account}:assumed-role/{role_name}/{function_name} is not authorized "
        f"to perform: dynamodb:PutItem on resource: {table_arn} because no identity-based policy "
        f"allows the dynamodb:PutItem action"
    )
    return full[:_HANDLER_MESSAGE_LIMIT]


def _invoke(lam, fn_name: str, event: dict[str, Any]) -> Any:
    """Invoke and decode, treating a handler error as a failure rather than a payload."""
    response = lam.invoke(FunctionName=fn_name, Payload=json.dumps(event).encode())
    body = response["Payload"].read()
    assert "FunctionError" not in response, (
        f"invoking {fn_name!r} raised {response.get('FunctionError')!r}: {body[:400]!r}"
    )
    return json.loads(body)


def _poll_until(fn, predicate, *, deadline_s: float, reason: str, interval_s: float = 5.0) -> Any:
    """Call *fn* until *predicate* accepts its result; raise naming *reason* on timeout."""
    deadline = time.monotonic() + deadline_s
    last: Any = "never called"
    while time.monotonic() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waiting for {reason} timed out after {deadline_s}s; last observation {last!r}"
    )


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
