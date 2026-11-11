"""cdk-function-default-props-grant-real-log-writes."""
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

CHECK = "cdk-function-default-props-grant-real-log-writes"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_DEPLOY_TIMEOUT_S = 600.0
_LOG_DEADLINE_S = 240.0
# IAM propagation into a Lambda execution environment can take minutes.
_PROPAGATION_DEADLINE_S = 600.0
_TEARDOWN_DEADLINE_S = 300.0

#: The absence hold never falls below this, even if the positive control was instant.
_MIN_ABSENCE_HOLD_S = 45.0

_APP = "cdk_fn_defaults"
_LOG_PREFIX = "SIM2REAL-LOG-MARKER "
_REPAIR_POLICY = "sim2real-log-writes"
_REPAIR_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "*",
    }],
}


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A default-props CDK Function gets a role with only AWSLambdaBasicExecutionRole that delivers
    logs; a policy-less twin runs but never logs until an inline policy grants the same log actions.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]

    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-cdkfndef-")
    app_context = {"account": account, "region": ctx.region, "stack_name": stack}
    work = _stage_app(ctx, _APP)

    plain_group = deprived_group = None
    repair_put = False
    deprived_role: str | None = None

    def _cleanup() -> None:
        extra: list[tuple[str, Any]] = []
        if deprived_role and repair_put:
            # A policy CloudFormation did not create would block its delete of the role.
            extra.append((
                f"inline policy {_REPAIR_POLICY} on {deprived_role}",
                lambda: _delete_role_policy(iam, deprived_role, _REPAIR_POLICY),
            ))
        # Lambda-created log groups live OUTSIDE the stack and outlive `cdk destroy`. Their names are
        # CDK-generated, so no prefix search can match them: delete by exact name or leak.
        after = [
            (f"log group {group}", lambda g=group: _reap_log_group(logs, g))
            for group in (plain_group, deprived_group) if group
        ]
        _teardown(ctx, [stack], extra, after)

    ctx.on_cleanup(_cleanup)

    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], app_context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = _stack_outputs(ctx, stack)
    for key in ("PlainFunctionName", "PlainRoleName", "RetainedFunctionName",
                "RetainedLogGroupName", "DeprivedFunctionName", "DeprivedRoleName"):
        assert key in outputs, (
            f"the deployed stack's Outputs are {sorted(outputs)!r}, expected {key!r}"
        )
    plain_fn = outputs["PlainFunctionName"]
    plain_role = outputs["PlainRoleName"]
    retained_fn = outputs["RetainedFunctionName"]
    retained_group = outputs["RetainedLogGroupName"]
    deprived_fn = outputs["DeprivedFunctionName"]
    deprived_role = outputs["DeprivedRoleName"]
    plain_group = f"/aws/lambda/{plain_fn}"
    deprived_group = f"/aws/lambda/{deprived_fn}"

    # ---- 1. the DEPLOYED role, read from IAM, not from the template -------------------------
    attached = iam.list_attached_role_policies(RoleName=plain_role)["AttachedPolicies"]
    assert [p["PolicyName"] for p in attached] == ["AWSLambdaBasicExecutionRole"], (
        f"the default-props function's role {plain_role!r} has attached managed policies "
        f"{[p['PolicyName'] for p in attached]!r}, expected exactly "
        f"['AWSLambdaBasicExecutionRole'] — the Function L2 attaches that one policy and nothing "
        f"else"
    )
    inline = iam.list_role_policies(RoleName=plain_role)["PolicyNames"]
    assert inline == [], (
        f"the default-props function's role {plain_role!r} carries inline policies {inline!r}; "
        f"with no grants requested the L2 must add none"
    )

    # ---- 2. the BEHAVIOURAL proof of that policy, and the latency calibration ---------------
    plain_marker = ctx.unique_name("plain-")
    started = time.monotonic()
    echoed = _invoke(lam, plain_fn, {"marker": plain_marker})
    assert echoed["echoed"] == plain_marker, (
        f"invoking {plain_fn!r} returned {echoed!r}, expected its 'echoed' field to be "
        f"{plain_marker!r}"
    )
    _poll_until(
        lambda: _log_marker_present(logs, plain_group, plain_marker),
        lambda found: found,
        deadline_s=_LOG_DEADLINE_S,
        reason=(f"the default-props function's print() to reach CloudWatch Logs group "
                f"{plain_group!r} — log delivery is asynchronous"),
        interval_s=3.0,
    )
    positive_latency_s = time.monotonic() - started

    # ---- 3. the default retention is never-expire, with a twin that proves it is a choice ---
    plain_described = _one_log_group(logs, plain_group)
    assert "retentionInDays" not in plain_described, (
        f"the default-props function's log group {plain_group!r} reports "
        f"retentionInDays={plain_described.get('retentionInDays')!r}; the Function L2 sets no "
        f"retention, so the deployed group must have the key absent (never expire). Full group: "
        f"{ {k: v for k, v in plain_described.items() if k != 'arn'} !r}"
    )
    retained_described = _one_log_group(logs, retained_group)
    assert retained_described.get("retentionInDays") == 1, (
        f"the twin control group {retained_group!r} reports "
        f"retentionInDays={retained_described.get('retentionInDays')!r}, expected 1 — the same "
        f"stack asked for RetentionDays.ONE_DAY, so a target that cannot set retention at all "
        f"fails here while passing the never-expire assertion above"
    )
    # The custom group is really the one the function logs to, not merely declared beside it.
    retained_marker = ctx.unique_name("retained-")
    _invoke(lam, retained_fn, {"marker": retained_marker})
    _poll_until(
        lambda: _log_marker_present(logs, retained_group, retained_marker),
        lambda found: found,
        deadline_s=_LOG_DEADLINE_S,
        reason=(f"the Retained function's print() to reach its EXPLICIT group "
                f"{retained_group!r}, proving LoggingConfig.LogGroup is honoured"),
        interval_s=3.0,
    )

    # ---- 4. NEGATIVE: Lambda needs no logs permission to run, so the policy is the cause ----
    deprived_attached = iam.list_attached_role_policies(RoleName=deprived_role)[
        "AttachedPolicies"]
    deprived_inline = iam.list_role_policies(RoleName=deprived_role)["PolicyNames"]
    assert deprived_attached == [] and deprived_inline == [], (
        f"the deprived role {deprived_role!r} was expected to hold no policies at all but has "
        f"attached={[p['PolicyArn'] for p in deprived_attached]!r} inline={deprived_inline!r} — "
        f"the negative arm's premise does not hold"
    )
    deprived_marker = ctx.unique_name("deprived-")
    deprived_echo = _invoke(lam, deprived_fn, {"marker": deprived_marker})
    assert deprived_echo["echoed"] == deprived_marker, (
        f"the policy-less function {deprived_fn!r} did not even run: {deprived_echo!r}. It must "
        f"execute — Lambda needs no logs permission to run — otherwise this arm proves nothing "
        f"about logging"
    )
    # Calibrated window: at least 3x the latency the SAME wiring just demonstrated.
    hold_s = max(_MIN_ABSENCE_HOLD_S, 3.0 * positive_latency_s)
    hold_deadline = time.monotonic() + hold_s
    while time.monotonic() < hold_deadline:
        groups = logs.describe_log_groups(logGroupNamePrefix=deprived_group)["logGroups"]
        assert groups == [], (
            f"the policy-less function's log group {deprived_group!r} exists "
            f"({[g['logGroupName'] for g in groups]!r}) — without "
            f"AWSLambdaBasicExecutionRole the function cannot call logs:CreateLogGroup"
        )
        time.sleep(5.0)
    # A second, independent observable of the same absence.
    assert _error_code(
        lambda: logs.filter_log_events(logGroupName=deprived_group)
    ) == ("ResourceNotFoundException", "The specified log group does not exist."), (
        f"FilterLogEvents on {deprived_group!r} did not report ResourceNotFoundException after "
        f"{hold_s:.0f}s (>= 3x the {positive_latency_s:.1f}s the positive control took on "
        f"identical wiring) — the group exists in some form"
    )

    # ---- 5. RESTORE: grant the same log actions inline and demand the logs appear -----------
    repair_put = True
    iam.put_role_policy(RoleName=deprived_role, PolicyName=_REPAIR_POLICY,
                        PolicyDocument=json.dumps(_REPAIR_DOCUMENT))
    repaired_marker = ctx.unique_name("repaired-")

    def _invoke_on_a_fresh_environment() -> bool:
        # Re-invoking a WARM environment proves nothing: it may keep serving the credentials it
        # assumed before the attach for its whole life, however long that is. Only
        # UpdateFunctionConfiguration is documented to retire every live environment, so force a
        # NEW one on every attempt — a single forced cold start only re-rolls the propagation
        # race once, and a loser there would then poll a never-changing answer forever.
        lam.update_function_configuration(
            FunctionName=deprived_fn,
            Environment={"Variables": {"SIM2REAL_FORCE_COLD": ctx.unique_name("cold-")}},
        )
        _wait_updated(lam, deprived_fn)
        _invoke(lam, deprived_fn, {"marker": repaired_marker})
        return _log_marker_present(logs, deprived_group, repaired_marker)

    _poll_until(
        _invoke_on_a_fresh_environment, lambda found: found,
        deadline_s=_PROPAGATION_DEADLINE_S,
        reason=(f"the inline policy {_REPAIR_POLICY} to take effect for "
                f"{deprived_fn!r} on a freshly forced execution environment — IAM's own "
                f"propagation to STS AssumeRole is asynchronous even once each environment is "
                f"fresh"),
        interval_s=15.0,
    )
    # TERMINAL READ: the log bytes, at CloudWatch Logs, for the function whose only changes were
    # the inline policy and the configuration touch that retires warm environments. Read once
    # more so the assertion does not rest on the poll's predicate.
    assert _log_marker_present(logs, deprived_group, repaired_marker), (
        f"the marker {repaired_marker!r} is not in {deprived_group!r} on a second, independent "
        f"read — the restore beat did not hold"
    )


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


def _invoke(lam, fn_name: str, event: dict[str, Any]) -> Any:
    """Invoke and decode, treating a handler error as a failure rather than a payload."""
    response = lam.invoke(FunctionName=fn_name, Payload=json.dumps(event).encode())
    body = response["Payload"].read()
    assert "FunctionError" not in response, (
        f"invoking {fn_name!r} raised {response.get('FunctionError')!r}: {body[:400]!r}"
    )
    return json.loads(body)


def _error_code(fn) -> tuple[str, str]:
    """The AWS error code and message a call raises.

    Raises when the call SUCCEEDS: an unexpected success is the strongest possible signal about a
    target.
    """
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), exc.response["Error"].get("Message", "")
    raise AssertionError("call succeeded but was expected to be refused")


def _poll_until(fn, predicate, *, deadline_s: float, reason: str, interval_s: float = 5.0) -> Any:
    """Call *fn* until *predicate* accepts its result; raise on timeout naming *reason*."""
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


def _wait_updated(lam, fn: str, *, timeout_s: float = 60.0) -> None:
    """Block until *fn*'s LastUpdateStatus leaves InProgress; raise on Failed or timeout."""
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        status = last.get("LastUpdateStatus")
        if status == "Successful":
            return
        if status == "Failed":
            raise AssertionError(
                f"configuration update for {fn!r} failed: {last.get('LastUpdateStatusReason')!r}"
            )
        time.sleep(1.0)
    raise AssertionError(
        f"{fn!r} LastUpdateStatus did not reach Successful within {timeout_s}s; last {last!r}"
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


def _delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    """Delete inline *policy_name* from *role_name*; a put that never landed is not a failure."""
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _log_marker_present(logs, group_name: str, marker: str) -> bool:
    """Whether *marker* appears in any event of *group_name*. False when the group does not exist.

    Every caller polls for True with a raising deadline or asserts True, so False cannot pass.
    """
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=group_name, filterPattern=f'"{_LOG_PREFIX}{marker}"')
        for page in pages:
            for event in page.get("events", []):
                if marker in event["message"]:
                    return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return False


def _one_log_group(logs, group_name: str) -> dict[str, Any]:
    """The single log group named exactly *group_name*. Fails loudly if it is absent or ambiguous."""
    matches = [
        group for group in logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"]
        if group["logGroupName"] == group_name
    ]
    assert len(matches) == 1, (
        f"DescribeLogGroups for prefix {group_name!r} matched {len(matches)} groups with that exact "
        f"name, expected exactly 1"
    )
    return matches[0]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
