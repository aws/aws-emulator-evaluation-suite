"""cdk-custom-resource-provider-waits-for-iscomplete."""
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

CHECK = "cdk-custom-resource-provider-waits-for-iscomplete"
GROUP = "deploy-custom-resource"
SERVICES = ["cloudformation", "dynamodb", "lambda"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_APP = "cdk_custom_resource_waiter"
_ON_EVENT_PLACEHOLDER = "unset-by-on-event"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A `custom_resources.Provider` custom resource must reach CREATE_COMPLETE only once its
    isComplete handler reports done, publish THAT handler's Data under Fn::GetAtt rather than
    onEvent's, and keep its Ref stable across an update whose onEvent response never changes it.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack_name = ctx.unique_name("sim2real-cdkwaiter-")
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"

    base_context = {"account": account, "region": ctx.region, "stack_name": stack_name,
                     "qualifier": qualifier}
    seed1 = ctx.unique_name("seed1-")
    seed2 = ctx.unique_name("seed2-")

    work = _stage_app(ctx, _APP)
    bootstrap_started = False
    fn_names: list[str] = []

    try:
        # Owned from launch: a failed or timed-out bootstrap can still leave the toolkit stack
        # and its retained staging bucket behind.
        bootstrap_started = True
        _bootstrap(ctx, account, qualifier, toolkit_stack)

        # Create: isComplete must report done before CREATE_COMPLETE, and its Data -- not
        # onEvent's placeholder -- must be what the stack output exposes.
        _cdk(ctx, work, ["deploy", stack_name, "--require-approval", "never"],
             {**base_context, "seed": seed1}, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        physical_id1, value1 = _stack_outputs(ctx, stack_name, "PhysicalId", "Value")
        fn_names = _lambda_function_names(ctx, stack_name)

        assert value1 == f"computed-{seed1}", (
            f"stack output Value was {value1!r}, expected {f'computed-{seed1}'!r} -- the custom "
            f"resource's attribute must come from isComplete's response; onEvent only ever "
            f"returns the placeholder {_ON_EVENT_PLACEHOLDER!r}, so this value could only have "
            f"reached the output through isComplete (which itself only answers True on a later "
            f"call than the one that created this state, forcing a real asynchronous wait)"
        )

        # Update: only Seed changes. onEvent's PhysicalResourceId never depends on Seed, so the
        # custom resource must be updated in place, not replaced -- and the update must itself
        # wait for its own isComplete call to report done.
        _cdk(ctx, work, ["deploy", stack_name, "--require-approval", "never"],
             {**base_context, "seed": seed2}, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        physical_id2, value2 = _stack_outputs(ctx, stack_name, "PhysicalId", "Value")

        assert physical_id2 == physical_id1, (
            f"after an update that only changed Seed, Ref of the custom resource became "
            f"{physical_id2!r}, expected the create-time id {physical_id1!r} to survive -- "
            f"onEvent computes the same PhysicalResourceId regardless of Seed, so this update "
            f"must not have replaced the resource"
        )
        assert value2 == f"computed-{seed2}", (
            f"after update, stack output Value was {value2!r}, expected {f'computed-{seed2}'!r} "
            f"-- the update's isComplete response must reach the output just as the create's did"
        )
    finally:
        if not fn_names and bootstrap_started:
            try:
                fn_names = _lambda_function_names(ctx, stack_name)
            except Exception:  # noqa: BLE001 — best-effort before teardown, never the verdict
                fn_names = []
        _teardown(ctx, stack_name, staging_bucket, toolkit_stack, qualifier, account, fn_names,
                  bootstrap_started)


def _lambda_function_names(ctx, stack: str) -> list[str]:
    """Every AWS::Lambda::Function physical id in the stack (ours and the Provider's own)."""
    cfn = ctx.client("cloudformation")
    names: list[str] = []
    for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack):
        for res in page["StackResourceSummaries"]:
            if res["ResourceType"] == "AWS::Lambda::Function":
                names.append(res["PhysicalResourceId"])
    return names


def _bootstrap(ctx, account: str, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci", "--no-notices",
        "--tags", f"sim2real={CHECK}",
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0. "
        f"Output tail: {(result.stdout + result.stderr)[-1000:]!r}"
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


def _stack_outputs(ctx, stack: str, *keys: str) -> list[str]:
    """The stack's Outputs `keys`, read from CloudFormation; asserts every key is present."""
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] in ("CREATE_COMPLETE", "UPDATE_COMPLETE"), (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE or "
        f"UPDATE_COMPLETE before reading its outputs"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}
    missing = [key for key in keys if key not in outputs]
    assert not missing, (
        f"stack {stack!r} has no Output(s) {missing!r}; it exposes {sorted(outputs)!r}"
    )
    return [outputs[key] for key in keys]


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if (exc.response["Error"]["Code"] == "ValidationError"
                    and "does not exist" in exc.response["Error"].get("Message", "")):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Purge every version and delete marker, then the bucket. Only this run's staging bucket."""
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


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 3.0,
                    budget_s: float = 90.0) -> None:
    """Delete log group `name` until `reads` consecutive reads find it absent.

    A Lambda-created log group is not a stack resource, and a buffered flush can recreate it
    right after the stack's own delete -- so this is a loop, not a single delete.
    """
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
                    f"log group {name!r} still present after {budget_s}s of deletes; "
                    f"{absent} clean reads"
                )
            time.sleep(interval_s)


def _bootstrap_remnants(ctx, staging_bucket: str, qualifier: str, account: str) -> list[str]:
    """What bootstrap left behind, by exact name; only a resource's own not-found is absence."""
    remaining: list[str] = []
    try:
        ctx.client("s3").head_bucket(Bucket=staging_bucket)
        remaining.append(f"staging bucket {staging_bucket}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("404", "NoSuchBucket"):
            raise
    parameter = f"/cdk-bootstrap/{qualifier}/version"
    try:
        ctx.client("ssm").get_parameter(Name=parameter)
        remaining.append(f"ssm parameter {parameter}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    repository = f"cdk-{qualifier}-container-assets-{account}-{ctx.region}"
    try:
        ctx.client("ecr").describe_repositories(repositoryNames=[repository])
        remaining.append(f"ecr repository {repository}")
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


def _teardown(ctx, stack: str, staging_bucket: str, toolkit_stack: str, qualifier: str,
              account: str, fn_names: list[str], bootstrap_started: bool) -> None:
    """Delete the app stack, reap its Lambda functions' log groups, then everything bootstrap
    left, in that order -- the log-group race is specific to Lambda and only follows the stack
    delete; bootstrap teardown outlasts `ctx.on_cleanup`'s cap, so it runs inline here instead.
    """
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    logs = ctx.client("logs")
    problems: list[str] = []
    steps: list[tuple[str, Any]] = [
        (f"app stack {stack}",
         lambda: _delete_stack_and_wait(ctx, stack, timeout_s=max(30.0, deadline - time.monotonic()))),
    ]
    for fn_name in fn_names:
        steps.append((f"log group /aws/lambda/{fn_name}",
                      lambda n=fn_name: _reap_log_group(
                          logs, f"/aws/lambda/{n}",
                          budget_s=max(10.0, min(90.0, deadline - time.monotonic())))))
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    if bootstrap_started and any(p.startswith(f"app stack {stack}:") for p in problems):
        # The app stack deletes as the toolkit's exec role: deleting the toolkit now strands it.
        problems.append(f"toolkit stack {toolkit_stack} and staging bucket kept: "
                        f"app stack not deleted")
        bootstrap_started = False
    toolkit_steps: list[tuple[str, Any]] = [] if not bootstrap_started else [
        (f"staging bucket {staging_bucket}",
         lambda: _empty_and_delete_bucket(ctx, staging_bucket)),
        (f"toolkit stack {toolkit_stack}",
         lambda: _delete_stack_and_wait(ctx, toolkit_stack,
                                        timeout_s=max(30.0, deadline - time.monotonic()))),
    ]
    for label, step in toolkit_steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")

    if bootstrap_started:
        try:
            remaining = _bootstrap_remnants(ctx, staging_bucket, qualifier, account)
        except Exception as exc:  # noqa: BLE001 — raised with every failure collected so far
            problems.append(f"bootstrap remnant check: {exc!r}")
            raise AssertionError("teardown left residue: " + "; ".join(problems)) from exc
        else:
            if remaining:
                problems.append(f"bootstrap remnants still present: {remaining!r}")
    if problems:
        raise AssertionError("teardown left residue: " + "; ".join(problems))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
