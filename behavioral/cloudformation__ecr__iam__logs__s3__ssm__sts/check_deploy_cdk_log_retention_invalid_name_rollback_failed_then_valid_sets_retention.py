"""deploy-cdk-log-retention-invalid-name-rollback-failed-then-valid-sets-retention."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-log-retention-invalid-name-rollback-failed-then-valid-sets-retention"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "iam", "logs", "s3", "ssm", "sts"]

_APP = "cdk_log_retention"

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_TEARDOWN_DEADLINE_S = 420.0

_FAILURE_PREFIX = "Received response status [FAILED] from custom resource. Message returned: "
_INVALID_NAME_MESSAGE = (
    "1 validation error detected: Value at 'logGroupName' failed to satisfy constraint: Member "
    "must satisfy regular expression pattern: [\\.\\-_/#A-Za-z0-9]+"
)


_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _assert_invalid_name_failure(reason: str, label: str) -> None:
    """Assert ``reason`` is exactly the wrapped invalid-name message, its trailing RequestId
    masked."""
    masked = re.sub(rf" \(RequestId: {_UUID}\)$", " (RequestId: <id>)", reason)
    want = _FAILURE_PREFIX + _INVALID_NAME_MESSAGE + " (RequestId: <id>)"
    assert masked == want, f"the {label} failure reason was {reason!r}, expected {want!r}"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Custom::LogRetention Create on an invalid name fails, and the rollback's Delete reissues the
    same call and fails too, leaving ROLLBACK_FAILED with nothing created; a valid name creates the
    log group at RetentionInDays, updates it, and DESTROY removes it.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    logs = ctx.client("logs")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    bad_stack = ctx.unique_name("sim2real-logret-bad-")
    good_stack = ctx.unique_name("sim2real-logret-good-")
    bad_log_group = "/sim2real/" + ctx.unique_name("logret-bad-") + "!invalid"
    good_log_group = "/sim2real/" + ctx.unique_name("logret-good-")
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"

    work = _stage_app(ctx, _APP)
    fn_names: list[str] = []
    try:
        _bootstrap(ctx, account, qualifier, toolkit_stack)

        # 1. REJECTED: AWS refuses the invalid log group name on Create; the automatic rollback's
        #    Delete event reissues the same call against the same name and fails identically,
        #    leaving the stack stuck in ROLLBACK_FAILED rather than ROLLBACK_COMPLETE.
        rc, out = _cdk(
            ctx,
            work,
            ["deploy", bad_stack, "--require-approval", "never"],
            _env(ctx, account, qualifier, bad_stack, bad_log_group, "7"),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=None,
        )
        fn_names.extend(_stack_lambda_functions(cfn, bad_stack))
        assert rc != 0, (
            f"`cdk deploy` exited 0 deploying a Custom::LogRetention naming the invalid log "
            f"group {bad_log_group!r}. Output tail: {out[-800:]!r}"
        )
        status = _wait_terminal_status(cfn, bad_stack, ctx=ctx)
        assert status == "ROLLBACK_FAILED", (
            f"stack {bad_stack!r} reached {status!r}, expected ROLLBACK_FAILED — the rollback's "
            f"Delete event reissues the same refused call"
        )
        _, create_reason, delete_reason = _retention_failure_reasons(cfn, bad_stack)
        _assert_invalid_name_failure(create_reason, "Create")
        _assert_invalid_name_failure(delete_reason, "rollback Delete")
        # The invalid "!" makes the full name itself an illegal prefix to search on; the valid
        # portion before it is still a prefix nothing could have landed under.
        valid_prefix = bad_log_group.split("!", 1)[0]
        missing_groups = logs.describe_log_groups(logGroupNamePrefix=valid_prefix)["logGroups"]
        assert missing_groups == [], (
            f"after the refused create, DescribeLogGroups for prefix {valid_prefix!r} returned "
            f"{missing_groups!r}, expected none — a refusal must create nothing"
        )

        # 2. CREATE (control): the identical construct against a name AWS accepts creates the
        #    log group with the declared RetentionInDays.
        _cdk(
            ctx,
            work,
            ["deploy", good_stack, "--require-approval", "never"],
            _env(ctx, account, qualifier, good_stack, good_log_group, "7"),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=0,
        )
        fn_names.extend(_stack_lambda_functions(cfn, good_stack))
        created = _one_log_group(logs, good_log_group)
        assert created["retentionInDays"] == 7, (
            f"log group {good_log_group!r} has retentionInDays={created.get('retentionInDays')!r} "
            f"after create, expected 7"
        )

        # 3. UPDATE: a changed retention value is applied in place to the same log group.
        _cdk(
            ctx,
            work,
            ["deploy", good_stack, "--require-approval", "never"],
            _env(ctx, account, qualifier, good_stack, good_log_group, "14"),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=0,
        )
        updated = _one_log_group(logs, good_log_group)
        assert updated["retentionInDays"] == 14, (
            f"log group {good_log_group!r} has retentionInDays={updated.get('retentionInDays')!r} "
            f"after the update, expected 14"
        )

        # 4. DESTROY: the explicit DESTROY removal policy deletes the log group with the stack.
        _cdk(
            ctx,
            work,
            ["destroy", good_stack, "--force"],
            _env(ctx, account, qualifier, good_stack, good_log_group, "14"),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=0,
        )
        _wait_for_stack_absent(ctx, cfn, good_stack)
        gone = logs.describe_log_groups(logGroupNamePrefix=good_log_group)["logGroups"]
        assert gone == [], (
            f"after the stack was destroyed, DescribeLogGroups for prefix {good_log_group!r} "
            f"returned {gone!r}, expected none — the DESTROY removal policy must delete the "
            f"log group"
        )
    except BaseException as body_exc:
        # Tear down without letting a teardown error replace the body's own failure.
        try:
            _teardown(
                ctx,
                account,
                [bad_stack, good_stack],
                toolkit_stack,
                staging_bucket,
                qualifier,
                fn_names,
                [good_log_group],
            )
        except Exception as teardown_exc:
            body_exc.add_note(f"teardown also failed: {teardown_exc!r}")
        raise
    _teardown(
        ctx,
        account,
        [bad_stack, good_stack],
        toolkit_stack,
        staging_bucket,
        qualifier,
        fn_names,
        [good_log_group],
    )


def _env(
    ctx, account: str, qualifier: str, stack: str, log_group_name: str, retention_days: str
) -> dict[str, str]:
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = account
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["LOG_GROUP_NAME"] = log_group_name
    env["RETENTION_DAYS"] = retention_days
    return env


def _retention_failure_reasons(cfn, stack: str) -> tuple[str, str, str]:
    """``(logical id, Create failure reason, Delete failure reason)`` of the one Custom::LogRetention,
    each from its single CREATE_FAILED and DELETE_FAILED row."""
    rows = [
        event
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack)
        for event in page["StackEvents"]
        if event["ResourceType"] == "Custom::LogRetention"
    ]
    created = [e for e in rows if e["ResourceStatus"] == "CREATE_FAILED"]
    deleted = [e for e in rows if e["ResourceStatus"] == "DELETE_FAILED"]
    assert (len(created), len(deleted)) == (1, 1), (
        f"stack {stack!r}: expected one CREATE_FAILED and one DELETE_FAILED Custom::LogRetention "
        f"row, got {[(e['LogicalResourceId'], e['ResourceStatus']) for e in created + deleted]!r}"
    )
    return (
        created[0]["LogicalResourceId"],
        created[0].get("ResourceStatusReason", ""),
        deleted[0].get("ResourceStatusReason", ""),
    )


def _force_delete_stuck_stack(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete ``stack``, retaining its CREATE_FAILED resources if a plain delete cannot finish.

    A Custom::LogRetention that never created anything leaves nothing behind when retained.
    """
    cfn = ctx.client("cloudformation")
    try:
        stack = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if _is_stack_not_found(exc, stack):
            return
        raise
    deadline = time.monotonic() + timeout_s
    status = _wait_terminal_status(cfn, stack, timeout_s=timeout_s)
    if status == "DELETE_COMPLETE":
        return
    if status == "ROLLBACK_FAILED":
        # AWS only accepts RetainResources once the stack is itself DELETE_FAILED: a plain
        # delete on a ROLLBACK_FAILED stack reissues the same refused call and fails the same
        # way, which is what gets it there.
        cfn.delete_stack(StackName=stack)
        status = _wait_terminal_status(cfn, stack, timeout_s=max(30.0, deadline - time.monotonic()))
    if status in ("ROLLBACK_FAILED", "DELETE_FAILED"):
        stuck = [
            e["LogicalResourceId"]
            for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack)
            for e in page["StackEvents"]
            if e["ResourceStatus"] in ("CREATE_FAILED", "DELETE_FAILED")
            and e["ResourceType"] != "AWS::CloudFormation::Stack"
        ]
        cfn.delete_stack(StackName=stack, RetainResources=sorted(set(stuck)))
    else:
        cfn.delete_stack(StackName=stack)
    _wait_for_stack_absent(None, cfn, stack, timeout_s=max(30.0, deadline - time.monotonic()))


def _one_log_group(logs, name: str) -> dict:
    groups = [
        g
        for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if g["logGroupName"] == name
    ]
    assert len(groups) == 1, f"expected exactly one log group named {name!r}, found {groups!r}"
    return groups[0]


def _stack_lambda_functions(cfn, stack: str) -> list[str]:
    names: list[str] = []
    try:
        for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack):
            for res in page["StackResourceSummaries"]:
                if res["ResourceType"] == "AWS::Lambda::Function" and res.get("PhysicalResourceId"):
                    names.append(res["PhysicalResourceId"])
    except ClientError as exc:
        if not _is_stack_not_found(exc, stack):
            raise
    return names


def _is_stack_not_found(exc: ClientError, stack: str) -> bool:
    """Whether ``exc`` is exactly CloudFormation's not-found for the stack name or id ``stack``."""
    error = exc.response["Error"]
    return (error.get("Code"), error.get("Message")) == (
        "ValidationError",
        f"Stack with id {stack} does not exist",
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _run_tool(ctx, cmd: list[str], cwd: Path, env: dict[str, str], timeout_s: float):
    """subprocess.run capped by the run budget; a run the budget ended raises TimeoutError."""
    try:
        return subprocess.run(
            cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=_budget_s(ctx, timeout_s)
        )
    except subprocess.TimeoutExpired:
        if _budget_spent(ctx):
            raise TimeoutError(
                f"`{' '.join(cmd[:2])}`: the run budget ended first; not graded"
            ) from None
        raise


def _stack_status(cfn, stack: str) -> str:
    """The status of the stack name or id ``stack``; the exact not-found reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if _is_stack_not_found(exc, stack):
            return "DELETE_COMPLETE"
        raise


def _poll_status(cfn, stack: str, done, timeout_s: float, ctx=None) -> str:
    """Poll the stack's status every 5 s until ``done(status)``; raise at the deadline."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = _stack_status(cfn, stack)
        if done(status):
            return status
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"stack {stack!r}: the run budget ended first; not graded")
            raise AssertionError(f"stack {stack!r} still {status!r} after {timeout_s:.0f}s")
        time.sleep(5.0)


def _stage_app(ctx, name: str) -> Path:
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), f"the CDK app this check references is missing: {source}"
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(
        source,
        staged,
        ignore=shutil.ignore_patterns("cdk.out", "out-*", ".venv", "__pycache__", "node_modules"),
    )
    return staged


def _cdk(
    ctx,
    work: Path,
    args: list[str],
    env: dict[str, str],
    *,
    timeout_s: float,
    expect_rc: int | None,
) -> tuple[int, str]:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-color", "--no-notices"]
    result = _run_tool(ctx, cmd, work, env, timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1500:]!r}"
        )
    return result.returncode, output


def _bootstrap(ctx, account: str, qualifier: str, toolkit_stack: str) -> None:
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk",
        "bootstrap",
        f"aws://{account}/{ctx.region}",
        "--qualifier",
        qualifier,
        "--toolkit-stack-name",
        toolkit_stack,
        "--bootstrap-kms-key-id",
        "AWS_MANAGED_KEY",
        "--ci",
        "--no-notices",
        "--tags",
        f"sim2real={CHECK}",
    ]
    result = _run_tool(ctx, command, scratch, ctx.subprocess_env(), _BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0; "
        f"output tail: {(result.stdout + result.stderr)[-1200:]!r}"
    )


def _wait_terminal_status(cfn, stack: str, *, timeout_s: float = 300.0, ctx=None) -> str:
    """Poll until the stack leaves every *_IN_PROGRESS state; raise at the deadline."""
    return _poll_status(cfn, stack, lambda s: not s.endswith("_IN_PROGRESS"), timeout_s, ctx)


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete the stack by its StackId, whatever its state; raise unless DELETE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if _is_stack_not_found(exc, stack):
            return
        raise
    deadline = time.monotonic() + timeout_s
    status = _poll_status(
        cfn,
        stack_id,
        lambda s: (
            not s.endswith("_IN_PROGRESS") or s in ("DELETE_IN_PROGRESS", "REVIEW_IN_PROGRESS")
        ),
        timeout_s,
    )
    if status != "DELETE_COMPLETE":
        cfn.delete_stack(StackName=stack_id)
        status = _poll_status(
            cfn,
            stack_id,
            lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
            max(30.0, deadline - time.monotonic()),
        )
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack!r} ({stack_id}) ended {status!r}, not DELETE_COMPLETE")


def _wait_for_stack_absent(ctx, cfn, stack: str, *, timeout_s: float = 420.0) -> None:
    """Wait until the stack name ``stack`` reads as gone; DELETE_FAILED raises at once."""
    status = _poll_status(
        cfn, stack, lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), timeout_s, ctx
    )
    assert status == "DELETE_COMPLETE", f"stack {stack!r} reached {status!r}"


def _delete_log_group(logs, name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _reap_log_group(
    ctx, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0
) -> None:
    logs = ctx.client("logs")
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
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
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes"
                )
            time.sleep(interval_s)


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _delete_ecr_repo(ctx, repo: str) -> None:
    try:
        ctx.client("ecr").delete_repository(repositoryName=repo, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _bootstrap_remnants(
    ctx, toolkit_stack: str, staging_bucket: str, qualifier: str, ecr_repo: str
) -> list[str]:
    remaining: list[str] = []
    try:
        status = ctx.client("cloudformation").describe_stacks(StackName=toolkit_stack)["Stacks"][0][
            "StackStatus"
        ]
        remaining.append(f"toolkit stack {toolkit_stack} ({status})")
    except ClientError as exc:
        if not _is_stack_not_found(exc, toolkit_stack):
            raise
    try:
        ctx.client("s3").head_bucket(Bucket=staging_bucket)
        remaining.append(f"staging bucket {staging_bucket}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("404", "NoSuchBucket"):
            raise
    try:
        ctx.client("ssm").get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
        remaining.append(f"ssm parameter /cdk-bootstrap/{qualifier}/version")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    try:
        ctx.client("ecr").describe_repositories(repositoryNames=[ecr_repo])
        remaining.append(f"container assets repository {ecr_repo}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise
    iam = ctx.client("iam")
    roles = [
        role["RoleName"]
        for page in iam.get_paginator("list_roles").paginate()
        for role in page["Roles"]
        if role["RoleName"].startswith(f"cdk-{qualifier}-")
    ]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


def _teardown(
    ctx,
    account: str,
    stacks: list[str],
    toolkit_stack: str | None,
    staging_bucket: str,
    qualifier: str,
    fn_names: list[str],
    log_groups: list[str],
) -> None:
    """Delete every app stack, its log groups, and the bootstrap, raising on any residue.

    Inline rather than `ctx.on_cleanup`, whose 60s cap cannot cover the bootstrap teardown.
    """
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    ecr_repo = f"cdk-{qualifier}-container-assets-{account}-{ctx.region}"
    # A deploy that failed before its functions were read still leaves their log groups.
    try:
        for stack in stacks:
            for name in _stack_lambda_functions(ctx.client("cloudformation"), stack):
                if name not in fn_names:
                    fn_names.append(name)
    except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
        problems.append(f"function names of the app stacks: {exc!r}")
    steps: list[tuple[str, object]] = [
        (
            f"app stack {stack}",
            lambda stack=stack: _force_delete_stuck_stack(
                ctx, stack, timeout_s=max(30.0, deadline - time.monotonic())
            ),
        )
        for stack in stacks
    ]
    for fn_name in fn_names:
        steps.append(
            (f"log group of {fn_name}", lambda n=fn_name: _reap_log_group(ctx, f"/aws/lambda/{n}"))
        )
    for name in log_groups:
        steps.append((f"log group {name}", lambda n=name: _delete_log_group(ctx.client("logs"), n)))
    if toolkit_stack:
        steps += [
            (
                f"staging bucket {staging_bucket}",
                lambda: _empty_and_delete_bucket(ctx, staging_bucket),
            ),
            (
                f"toolkit stack {toolkit_stack}",
                lambda: _delete_stack_and_wait(
                    ctx, toolkit_stack, timeout_s=max(30.0, deadline - time.monotonic())
                ),
            ),
            (f"container assets repository {ecr_repo}", lambda: _delete_ecr_repo(ctx, ecr_repo)),
        ]
    for label, step in steps:
        if label == f"staging bucket {staging_bucket}" and any(
            p.startswith("app stack ") for p in problems
        ):
            raise AssertionError(
                f"toolkit stack {toolkit_stack} and staging bucket kept: " + "; ".join(problems)
            )
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")

    if toolkit_stack:
        remaining: list[str] = ["teardown verification never ran"]
        try:
            while True:
                remaining = _bootstrap_remnants(
                    ctx, toolkit_stack, staging_bucket, qualifier, ecr_repo
                )
                if not remaining or time.monotonic() > deadline:
                    break
                time.sleep(5.0)
        except Exception as exc:  # noqa: BLE001 — raised with every failure collected so far
            problems.append(f"bootstrap remnant verification failed: {exc!r}")
            raise AssertionError("teardown left residue: " + "; ".join(problems)) from exc
        if remaining:
            problems.append(f"bootstrap remnants still present: {remaining!r}")
    if problems:
        raise AssertionError("teardown left residue: " + "; ".join(problems))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
