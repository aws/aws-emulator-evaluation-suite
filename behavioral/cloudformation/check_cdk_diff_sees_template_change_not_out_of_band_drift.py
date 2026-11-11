"""cdk-diff-sees-template-change-not-out-of-band-drift."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-diff-sees-template-change-not-out-of-band-drift"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_DEPLOY_TIMEOUT_S = 600.0
_DIFF_TIMEOUT_S = 300.0
_DRIFT_DEADLINE_S = 300.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_table_diffable"
_NO_DIFF_TEXT = "There were no differences"
_NO_DRIFT_TEXT = "No drift detected"


@tags("axis:happy-path", "cap:c2", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """`cdk diff` reports a local template change but not an out-of-band resource change, which
    `cdk drift` and DetectStackDrift report; the diff deploys nothing and the table keeps its rows.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/ref-cli-cmd-diff.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    ddb = ctx.client("dynamodb")

    stack = ctx.unique_name("sim2real-cdkdiff-")
    base = {"account": account, "region": ctx.region, "stack_name": stack}
    off = {**base, "pitr": "false"}
    on = {**base, "pitr": "true"}

    work = _stage_app(ctx, _APP)
    table_name: str | None = None
    drifted = False

    def _cleanup() -> None:
        extra: list[tuple[str, Any]] = []
        if drifted and table_name:
            extra.append((
                f"revert out-of-band PITR on {table_name}",
                lambda: ddb.update_continuous_backups(
                    TableName=table_name,
                    PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": False}),
            ))
        _teardown(ctx, [stack], extra)

    ctx.on_cleanup(_cleanup)

    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], off,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    table_name = _stack_outputs(ctx, stack)["TableName"]
    seed_key = ctx.unique_name("seed-")
    seed_marker = ctx.unique_name("seed-marker-")
    ddb.put_item(TableName=table_name,
                 Item={"pk": {"S": seed_key}, "marker": {"S": seed_marker}})
    assert _pitr_status(ddb, table_name) == "DISABLED", (
        f"the freshly deployed table {table_name!r} reports PITR "
        f"{_pitr_status(ddb, table_name)!r}, expected DISABLED — the app was synthesised with "
        f"pitr=false, so the rest of this check has no baseline"
    )

    # ---- 1. no-op diff on an unchanged stack ------------------------------------------------
    rc, output = _cdk(ctx, work, ["diff", stack, "--fail"], off,
                      timeout_s=_DIFF_TIMEOUT_S, expect_rc=None)
    assert rc == 0, (
        f"`cdk diff --fail` exited {rc} against the stack it had just deployed unchanged; a "
        f"no-op diff must exit 0. Output tail: {output[-800:]!r}"
    )
    assert _NO_DIFF_TEXT in output, (
        f"`cdk diff --fail` exited 0 on an unchanged stack but did not print "
        f"{_NO_DIFF_TEXT!r}; output tail: {output[-800:]!r}"
    )

    # ---- 2. a LOCAL change is reported, with the resource and property named -----------------
    rc, output = _cdk(ctx, work, ["diff", stack, "--fail"], on,
                      timeout_s=_DIFF_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk diff --fail` exited {rc} after point_in_time_recovery was flipped in the app, "
        f"expected 1. Output tail: {output[-1000:]!r}"
    )
    assert "AWS::DynamoDB::Table" in output, (
        f"`cdk diff` reported a difference without naming AWS::DynamoDB::Table; output tail: "
        f"{output[-1000:]!r}"
    )
    assert "PointInTimeRecoverySpecification" in output, (
        f"`cdk diff` reported a difference without naming the changed property "
        f"PointInTimeRecoverySpecification; output tail: {output[-1000:]!r}"
    )
    assert _NO_DIFF_TEXT not in output, (
        f"`cdk diff` printed {_NO_DIFF_TEXT!r} in the same run that exited 1; output tail: "
        f"{output[-1000:]!r}"
    )

    # ---- 3. effect-absent: a diff is a read ------------------------------------------------
    assert _pitr_status(ddb, table_name) == "DISABLED", (
        f"after `cdk diff` reported the PITR change, the DEPLOYED table {table_name!r} reports "
        f"PITR {_pitr_status(ddb, table_name)!r}, expected still DISABLED — `cdk diff` applied "
        f"the change it was only asked to describe"
    )

    # ---- 4. out-of-band drift is invisible to diff, visible to drift -----------------------
    ddb.update_continuous_backups(
        TableName=table_name,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )
    drifted = True
    _poll_until(
        lambda: _pitr_status(ddb, table_name),
        lambda status: status == "ENABLED",
        deadline_s=_DRIFT_DEADLINE_S,
        reason=("PITR to report ENABLED after UpdateContinuousBackups — DynamoDB reports "
                "ENABLING first"),
    )
    rc, output = _cdk(ctx, work, ["diff", stack, "--fail"], off,
                      timeout_s=_DIFF_TIMEOUT_S, expect_rc=None)
    assert rc == 0 and _NO_DIFF_TEXT in output, (
        f"`cdk diff --fail` exited {rc} after an OUT-OF-BAND resource change with the local app "
        f"matching the deployed template. It must exit 0 and print {_NO_DIFF_TEXT!r}: `cdk diff` "
        f"compares templates, never resources. Output tail: {output[-1000:]!r}"
    )
    # --unstable=drift is passed so a CLI version that gates drift behind it cannot turn an
    # unstable-flag error into a spurious exit code 1.
    rc, output = _cdk(ctx, work, ["drift", stack, "--fail", "--unstable=drift"], off,
                      timeout_s=_DIFF_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk drift --fail` exited {rc} while the deployed table's PITR was ENABLED and the "
        f"template says disabled, expected 1. Output tail: {output[-1000:]!r}"
    )
    assert _NO_DRIFT_TEXT not in output, (
        f"`cdk drift --fail` exited 1 but printed {_NO_DRIFT_TEXT!r}; output tail: "
        f"{output[-1000:]!r}"
    )
    # CloudFormation's own answer, on an independent API rather than the CLI's rendering.
    stack_drift, resource_drifts = _detect_drift(ctx, stack)
    assert stack_drift == "DRIFTED", (
        f"DetectStackDrift reported the stack {stack_drift!r} while its table's PITR had been "
        f"changed out of band, expected 'DRIFTED'"
    )
    table_drifts = [d for d in resource_drifts
                    if d["ResourceType"] == "AWS::DynamoDB::Table"]
    assert [d["StackResourceDriftStatus"] for d in table_drifts] == ["MODIFIED"], (
        f"the table's drift status was "
        f"{[d['StackResourceDriftStatus'] for d in table_drifts]!r}, expected exactly "
        f"['MODIFIED']"
    )

    # ---- 5. RESTORE: revert out of band, and drift must go quiet -----------------------------
    ddb.update_continuous_backups(
        TableName=table_name,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": False},
    )
    drifted = False
    _poll_until(
        lambda: _pitr_status(ddb, table_name),
        lambda status: status == "DISABLED",
        deadline_s=_DRIFT_DEADLINE_S,
        reason="PITR to report DISABLED again after the revert",
    )
    rc, output = _cdk(ctx, work, ["drift", stack, "--fail", "--unstable=drift"], off,
                      timeout_s=_DIFF_TIMEOUT_S, expect_rc=None)
    assert rc == 0 and _NO_DRIFT_TEXT in output, (
        f"`cdk drift --fail` exited {rc} after the out-of-band change was reverted, expected 0 "
        f"and {_NO_DRIFT_TEXT!r}. Without this arm, arm 4's exit code 1 could not be told from "
        f"'drift always reports drift'. Output tail: {output[-1000:]!r}"
    )

    # ---- TERMINAL READ: the table survived all of it, and still holds the seeded row ---------
    final_key = ctx.unique_name("final-")
    final_marker = ctx.unique_name("final-marker-")
    ddb.put_item(TableName=table_name,
                 Item={"pk": {"S": final_key}, "marker": {"S": final_marker}})
    final = ddb.get_item(TableName=table_name, Key={"pk": {"S": final_key}},
                         ConsistentRead=True).get("Item")
    assert final is not None and final.get("marker", {}).get("S") == final_marker, (
        f"after two PITR flips and five CDK CLI invocations, GetItem on {table_name!r} at "
        f"pk={final_key!r} returned {final!r}, expected marker {final_marker!r}"
    )
    seeded = ddb.get_item(TableName=table_name, Key={"pk": {"S": seed_key}},
                          ConsistentRead=True).get("Item")
    assert seeded is not None and seeded.get("marker", {}).get("S") == seed_marker, (
        f"the row written BEFORE the PITR flips is gone: GetItem at pk={seed_key!r} returned "
        f"{seeded!r}, expected marker {seed_marker!r} — a PITR change is an in-place update and "
        f"must not replace the table"
    )


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo.

    A missing app directory fails the check rather than being created."""
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

    `--no-version-reporting` drops CDK metadata, `--no-color` keeps ANSI out of asserted output."""
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
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's outputs file,
    so the CLI that deployed is not also the witness."""
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _poll_until(fn, predicate, *, deadline_s: float, reason: str, interval_s: float = 5.0) -> Any:
    """Call *fn* until *predicate* accepts its result; RAISE on timeout naming *reason*."""
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


def _teardown(ctx, stacks: list[str], extra: list[tuple[str, Any]] | None = None) -> None:
    """Run each extra, then delete each stack this run created; raise naming every failure."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    for label, fn in (extra or []):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — collected, then raised below
            problems.append(f"{label}: {exc!r}")
    for stack in stacks:
        try:
            _delete_stack_and_wait(ctx, stack, timeout_s=max(30.0, deadline - time.monotonic()))
        except Exception as exc:  # noqa: BLE001 — collected, then raised below
            problems.append(f"stack {stack}: {exc!r}")
    if problems:
        raise AssertionError("; ".join(problems))


def _pitr_status(ddb, table_name: str) -> str:
    """DynamoDB's own reported PITR status, via DescribeContinuousBackups."""
    backups = ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"]
    return str(backups["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"])


def _detect_drift(ctx, stack: str) -> tuple[str, list[dict[str, Any]]]:
    """CloudFormation's own drift verdict for *stack*: `(stack drift status, resource drifts)`.

    Detection is asynchronous: polled to DETECTION_COMPLETE, and DETECTION_FAILED is rejected."""
    cfn = ctx.client("cloudformation")
    detection_id = cfn.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
    status = _poll_until(
        lambda: cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id),
        lambda answer: answer["DetectionStatus"] == "DETECTION_COMPLETE",
        deadline_s=_DRIFT_DEADLINE_S,
        reason=(f"CloudFormation drift detection {detection_id!r} to complete — DetectStackDrift is "
                f"asynchronous and DETECTION_FAILED is deliberately NOT accepted here"),
    )
    # botocore has no paginator for this operation although the API pages with NextToken.
    drifts = []
    token = None
    while True:
        kw = {"StackName": stack}
        if token:
            kw["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kw)
        drifts.extend(page["StackResourceDrifts"])
        token = page.get("NextToken")
        if not token:
            break
    return str(status["StackDriftStatus"]), drifts
if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
