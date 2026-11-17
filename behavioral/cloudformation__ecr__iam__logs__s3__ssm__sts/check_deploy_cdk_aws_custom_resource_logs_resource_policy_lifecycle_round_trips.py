"""deploy-cdk-aws-custom-resource-logs-resource-policy-lifecycle-round-trips."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-aws-custom-resource-logs-resource-policy-lifecycle-round-trips"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "iam", "logs", "s3", "ssm", "sts"]

_APP = "cdk_logs_resource_policy"

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_TEARDOWN_DEADLINE_S = 420.0


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "plane:control",
    "resource:account-singleton:logs-resource-policy",
)
def run(ctx) -> None:
    """An AwsCustomResource's onCreate putResourcePolicy stores the declared statement for this
    log group, onUpdate replaces its actions in place, and destroying the stack removes the
    policy through onDelete.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    caller = ctx.client("sts").get_caller_identity()
    account = caller["Account"]
    partition = caller["Arn"].split(":")[1]
    logs = ctx.client("logs")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-logpol-")
    log_group_name = "/sim2real/" + ctx.unique_name("logpol-")
    policy_name = ctx.unique_name("sim2real-logpol-")
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"
    log_group_arn = f"arn:{partition}:logs:{ctx.region}:{account}:log-group:{log_group_name}:*"

    work = _stage_app(ctx, _APP)
    fn_names: list[str] = []
    try:
        _bootstrap(ctx, account, qualifier, toolkit_stack)

        # 1. CREATE: onCreate's putResourcePolicy lands a policy scoped to this log group.
        actions_v1 = ["logs:PutLogEvents"]
        _cdk(
            ctx,
            work,
            ["deploy", "--require-approval", "never"],
            _env(ctx, account, qualifier, stack, log_group_name, policy_name, actions_v1),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=0,
        )
        fn_names.extend(_stack_lambda_functions(cfn, stack))

        created_doc = json.loads(_one_policy(logs, policy_name)["policyDocument"])
        # AWS stores a single-element Action array as a bare string, not a one-item list.
        want_v1 = _document(actions_v1[0], log_group_arn, account)
        assert created_doc == want_v1, (
            f"the created policy document was {created_doc!r}, expected {want_v1!r}"
        )

        # 2. UPDATE: onUpdate's putResourcePolicy call replaces the document in place.
        actions_v2 = ["logs:PutLogEvents", "logs:CreateLogStream"]
        _cdk(
            ctx,
            work,
            ["deploy", "--require-approval", "never"],
            _env(ctx, account, qualifier, stack, log_group_name, policy_name, actions_v2),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=0,
        )
        updated_doc = json.loads(_one_policy(logs, policy_name)["policyDocument"])
        want_v2 = _document(actions_v2, log_group_arn, account)
        assert updated_doc == want_v2, (
            f"after the update, the policy document was {updated_doc!r}, expected {want_v2!r}"
        )

        # 3. DELETE: destroying the stack removes the resource policy.
        _cdk(
            ctx,
            work,
            ["destroy", "--force"],
            _env(ctx, account, qualifier, stack, log_group_name, policy_name, actions_v2),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=0,
        )
        _wait_for_stack_absent(ctx, cfn, stack)
        remaining = [
            p
            for p in logs.describe_resource_policies()["resourcePolicies"]
            if p["policyName"] == policy_name
        ]
        assert remaining == [], (
            f"after the stack was destroyed, DescribeResourcePolicies still lists "
            f"{remaining!r} for policy name {policy_name!r} — onDelete must remove the policy"
        )
    except BaseException as body_exc:
        # Tear down without letting a teardown error replace the body's own failure.
        try:
            _teardown(
                ctx,
                account,
                stack,
                toolkit_stack,
                staging_bucket,
                qualifier,
                fn_names,
                log_group_name,
                policy_name,
            )
        except Exception as teardown_exc:
            body_exc.add_note(f"teardown also failed: {teardown_exc!r}")
        raise
    _teardown(
        ctx,
        account,
        stack,
        toolkit_stack,
        staging_bucket,
        qualifier,
        fn_names,
        log_group_name,
        policy_name,
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


def _document(actions, log_group_arn: str, account: str) -> dict:
    """The policy document the app declares, with ``actions`` as AWS stores them."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2realAllowEventsWrite",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": actions,
                "Resource": log_group_arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": account}},
            }
        ],
    }


def _env(
    ctx,
    account: str,
    qualifier: str,
    stack: str,
    log_group_name: str,
    policy_name: str,
    actions: list[str],
) -> dict[str, str]:
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = account
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["LOG_GROUP_NAME"] = log_group_name
    env["POLICY_NAME"] = policy_name
    env["POLICY_ACTIONS"] = json.dumps(actions)
    return env


def _one_policy(logs, policy_name: str) -> dict:
    policies = [
        p
        for p in logs.describe_resource_policies()["resourcePolicies"]
        if p["policyName"] == policy_name
    ]
    assert len(policies) == 1, (
        f"expected exactly one resource policy named {policy_name!r}, found {policies!r}"
    )
    return policies[0]


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
    ctx, work: Path, args: list[str], env: dict[str, str], *, timeout_s: float, expect_rc: int
) -> None:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-color", "--no-notices"]
    result = _run_tool(ctx, cmd, work, env, timeout_s)
    output = result.stdout + result.stderr
    assert result.returncode == expect_rc, (
        f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output tail: "
        f"{output[-1500:]!r}"
    )


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


def _delete_resource_policy(logs, policy_name: str) -> None:
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    stack: str,
    toolkit_stack: str | None,
    staging_bucket: str,
    qualifier: str,
    fn_names: list[str],
    log_group_name: str,
    policy_name: str,
) -> None:
    """Delete the app stack, its log group and resource policy, and the bootstrap.

    Inline rather than `ctx.on_cleanup`, whose 60s cap cannot cover the bootstrap teardown.
    """
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    ecr_repo = f"cdk-{qualifier}-container-assets-{account}-{ctx.region}"
    logs = ctx.client("logs")
    # A deploy that failed before its functions were read still leaves their log groups.
    try:
        for name in _stack_lambda_functions(ctx.client("cloudformation"), stack):
            if name not in fn_names:
                fn_names.append(name)
    except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
        problems.append(f"function names of the app stack: {exc!r}")
    steps: list[tuple[str, object]] = [
        (
            f"app stack {stack}",
            lambda: _delete_stack_and_wait(
                ctx, stack, timeout_s=max(30.0, deadline - time.monotonic())
            ),
        ),
        (f"resource policy {policy_name}", lambda: _delete_resource_policy(logs, policy_name)),
        (f"log group {log_group_name}", lambda: _delete_log_group(logs, log_group_name)),
    ]
    for fn_name in fn_names:
        steps.append(
            (f"log group of {fn_name}", lambda n=fn_name: _reap_log_group(ctx, f"/aws/lambda/{n}"))
        )
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
