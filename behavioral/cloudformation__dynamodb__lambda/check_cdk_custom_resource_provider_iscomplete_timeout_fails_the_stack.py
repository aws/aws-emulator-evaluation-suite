"""cdk-custom-resource-provider-iscomplete-timeout-fails-the-stack."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-custom-resource-provider-iscomplete-timeout-fails-the-stack"
GROUP = "deploy-custom-resource"
SERVICES = ["cloudformation", "dynamodb", "lambda"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0
_TOTAL_TIMEOUT_S = 40

_APP = "cdk_custom_resource_waiter"
_TIMEOUT_REASON = "Operation timed out"
_CREATE_REQUEST_ID_MARKER = "REQUEST_ID=Create:"


# timing:real-time — workflow: 40 s
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e",
      "concern:negative-classes", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A `custom_resources.Provider` custom resource whose isComplete handler never reports done
    must fail the create, with the Provider's own timeout reason, rather than settle on
    whatever onEvent returned or hang past its own configured budget.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack_name = ctx.unique_name("sim2real-cdkwaiter-")
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"
    ecr_repo = f"cdk-{qualifier}-container-assets-{account}-{ctx.region}"
    seed = ctx.unique_name("seed-")

    work = _stage_app(ctx, _APP)

    try:
        _bootstrap(ctx, account, qualifier, toolkit_stack)

        context = {
            "account": account, "region": ctx.region, "stack_name": stack_name,
            "qualifier": qualifier, "seed": seed, "never_complete": "true",
            "total_timeout_s": str(_TOTAL_TIMEOUT_S),
        }
        rc, output = _cdk(ctx, work, ["deploy", stack_name, "--require-approval", "never"],
                          context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)

        assert rc != 0, (
            f"`cdk deploy` exited 0 with isComplete permanently returning False -- the Provider's "
            f"{_TOTAL_TIMEOUT_S}s total_timeout must fail the create, not let it settle. Output "
            f"tail: {output[-800:]!r}"
        )

        final_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        assert final_status == "ROLLBACK_COMPLETE", (
            f"stack {stack_name!r} ended {final_status!r}, expected ROLLBACK_COMPLETE -- a timed "
            f"out custom resource create must roll the stack back, not leave it CREATE_FAILED or "
            f"partially applied"
        )

        on_event_fn = _physical_id_for_logical(_lambda_functions(cfn, stack_name), "OnEvent",
                                               stack_name)
        request_id = _create_request_id_from_logs(logs, on_event_fn)
        expected_reason = (
            f"Received response status [FAILED] from custom resource. Message returned: "
            f"{_TIMEOUT_REASON} (RequestId: {request_id})"
        )
        reason = _resource_status_reason(cfn, stack_name, "Waited")
        assert reason == expected_reason, (
            f"the custom resource's CREATE_FAILED event carried reason {reason!r}, expected "
            f"exactly {expected_reason!r} -- CFN wraps the Provider framework's own timeout "
            f"reason with the request it was answering"
        )

        outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
        assert outputs == [], (
            f"a stack that rolled back from CREATE_FAILED published outputs {outputs!r}, expected "
            f"none -- a custom resource that never completed must not have any attribute readable"
        )
    finally:
        _teardown(ctx, cfn, logs, stack_name, staging_bucket, ecr_repo, toolkit_stack, qualifier)


def _resource_status_reason(cfn, stack: str, logical_id: str) -> str:
    """The ResourceStatusReason CloudFormation recorded for `logical_id`'s CREATE_FAILED event."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        for event in page["StackEvents"]:
            if (event["LogicalResourceId"] == logical_id
                    and event["ResourceStatus"] == "CREATE_FAILED"):
                return event.get("ResourceStatusReason", "")
    raise AssertionError(
        f"no CREATE_FAILED event found for logical resource {logical_id!r} in stack {stack!r}"
    )


def _lambda_functions(cfn, stack: str) -> dict[str, str]:
    """Every AWS::Lambda::Function in the stack (ours and the Provider's), logical -> physical."""
    return {
        res["LogicalResourceId"]: res["PhysicalResourceId"]
        for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack)
        for res in page["StackResourceSummaries"]
        if res["ResourceType"] == "AWS::Lambda::Function" and res.get("PhysicalResourceId")
    }


def _physical_id_for_logical(functions: dict[str, str], logical_id_prefix: str, stack: str) -> str:
    """The physical id of the one function CDK named from this construct id.

    CDK appends an 8-character address hash to the construct id to form the logical id, so this
    matches the prefix rather than the exact (synthesis-assigned) logical id.
    """
    matches = [phys for logical, phys in functions.items() if logical.startswith(logical_id_prefix)]
    assert len(matches) == 1, (
        f"expected exactly one AWS::Lambda::Function whose logical id starts with "
        f"{logical_id_prefix!r} in stack {stack!r}, found {matches!r}"
    )
    return matches[0]


def _create_request_id_from_logs(logs, function_name: str, *, timeout_s: float = 90.0) -> str:
    """The RequestId of the Create our onEvent handler logged, read back from its CloudWatch Logs.

    Every stream is read, so neither stream order nor the rollback's Delete line can pick the id.
    """
    deadline = time.monotonic() + timeout_s
    log_group = f"/aws/lambda/{function_name}"
    while time.monotonic() < deadline:
        found: set[str] = set()
        try:
            for page in logs.get_paginator("describe_log_streams").paginate(logGroupName=log_group):
                for stream in page["logStreams"]:
                    for event in _stream_events(logs, log_group, stream["logStreamName"]):
                        message = event["message"]
                        if _CREATE_REQUEST_ID_MARKER in message:
                            found.add(message.split(_CREATE_REQUEST_ID_MARKER, 1)[1].strip())
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        if found:
            assert len(found) == 1, (
                f"expected onEvent to log exactly one Create RequestId in {log_group}, "
                f"found {sorted(found)!r}"
            )
            return found.pop()
        time.sleep(3.0)
    raise AssertionError(
        f"no {_CREATE_REQUEST_ID_MARKER!r} line found in {log_group} within {timeout_s}s"
    )


def _stream_events(logs, log_group: str, stream_name: str) -> list[dict]:
    """Every event of one log stream, oldest first, following the forward token to its end."""
    events: list[dict] = []
    kwargs: dict[str, Any] = {"logGroupName": log_group, "logStreamName": stream_name,
                              "startFromHead": True}
    while True:
        page = logs.get_log_events(**kwargs)
        events += page["events"]
        token = page.get("nextForwardToken")
        if not page["events"] or not token or token == kwargs.get("nextToken"):
            return events
        kwargs["nextToken"] = token


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


def _stack_gone(exc: ClientError) -> bool:
    """True only for CloudFormation's own "stack does not exist" refusal."""
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in error.get("Message", "")


def _delete_stack_and_wait(cfn, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete, then poll to DELETE_COMPLETE; raises on DELETE_FAILED, any other error or timeout."""
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if _stack_gone(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_gone(exc):
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


def _bootstrap_remnants(ctx, staging_bucket: str, ecr_repo: str, qualifier: str) -> list[str]:
    """What bootstrap left behind, by exact name. Never a prefix sweep across the account."""
    remaining: list[str] = []
    try:
        ctx.client("s3").head_bucket(Bucket=staging_bucket)
        remaining.append(f"staging bucket {staging_bucket}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("404", "NoSuchBucket"):
            raise
    try:
        ctx.client("ecr").describe_repositories(repositoryNames=[ecr_repo])
        remaining.append(f"ecr repo {ecr_repo}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise
    try:
        ctx.client("ssm").get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
        remaining.append(f"ssm parameter /cdk-bootstrap/{qualifier}/version")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
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


def _teardown(ctx, cfn, logs, stack: str, staging_bucket: str, ecr_repo: str,
              toolkit_stack: str, qualifier: str) -> None:
    """Delete the app stack, reap its functions' log groups, then everything bootstrap left.

    Bootstrap stays while the app stack may remain, since its execution role is what deletes it.
    Called from run()'s finally: when the body failed, the residue is noted on that error.
    """
    found = sys.exc_info()[1]  # the body's failure in flight, if any
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []

    def run_step(label: str, step) -> bool:
        try:
            step()
            return True
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
            return False

    # Read the functions before the stack delete: each one's log group outlives the stack.
    fn_names: list[str] = []

    def collect() -> None:
        try:
            fn_names.extend(sorted(_lambda_functions(cfn, stack).values()))
        except ClientError as exc:
            if not _stack_gone(exc):
                raise

    run_step(f"functions of app stack {stack}", collect)
    stack_gone = run_step(
        f"app stack {stack}",
        lambda: _delete_stack_and_wait(cfn, stack,
                                       timeout_s=max(30.0, deadline - time.monotonic())))
    # After the stack delete: a buffered flush can recreate a group after a first delete.
    for fn_name in fn_names:
        run_step(f"log group /aws/lambda/{fn_name}",
                 lambda n=fn_name: _reap_log_group(
                     logs, f"/aws/lambda/{n}",
                     budget_s=max(10.0, min(90.0, deadline - time.monotonic()))))

    if not stack_gone:
        problems.append(f"toolkit stack {toolkit_stack} kept: the app stack delete did not "
                        f"complete")
    else:
        run_step(f"staging bucket {staging_bucket}",
                 lambda: _empty_and_delete_bucket(ctx, staging_bucket))
        run_step(f"toolkit stack {toolkit_stack}",
                 lambda: _delete_stack_and_wait(cfn, toolkit_stack,
                                                timeout_s=max(30.0, deadline - time.monotonic())))
        remaining = _bootstrap_remnants(ctx, staging_bucket, ecr_repo, qualifier)
        while remaining and time.monotonic() < deadline:
            time.sleep(5.0)
            remaining = _bootstrap_remnants(ctx, staging_bucket, ecr_repo, qualifier)
        if remaining:
            problems.append(f"bootstrap remnants still present after {_TEARDOWN_DEADLINE_S}s: "
                            f"{remaining!r}")
    if problems and found is not None:
        found.add_note("teardown left residue: " + "; ".join(problems))
    elif problems:
        raise AssertionError("teardown left residue: " + "; ".join(problems))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
