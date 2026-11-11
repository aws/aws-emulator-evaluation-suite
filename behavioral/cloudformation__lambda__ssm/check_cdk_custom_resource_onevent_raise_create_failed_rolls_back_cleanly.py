"""cdk-custom-resource-onevent-raise-create-failed-rolls-back-cleanly."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-custom-resource-onevent-raise-create-failed-rolls-back-cleanly"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "ssm"]

_APP = "cdk_cr_onevent_raises"
_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A custom_resources.Provider onEvent handler that raises on Create leaves the resource
    CREATE_FAILED (reason opens with the handler's text) and the stack ROLLBACK_COMPLETE, with
    the SSM parameter it would have written never created; unforced, the same app succeeds.

    Reference: https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.custom_resources.Provider.html
    """
    require_tools("cdk", "node")
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    fail_stack = ctx.unique_name("sim2real-cronevt-fail-")
    ok_stack = ctx.unique_name("sim2real-cronevt-ok-")
    param_fail = ctx.unique_name("/sim2real/cronevt-fail/")
    param_ok = ctx.unique_name("/sim2real/cronevt-ok/")
    marker_fail = ctx.unique_name("mfail-")
    marker_ok = ctx.unique_name("mok-")

    work = _stage_app(ctx, _APP)

    try:
        _bootstrap(ctx, qualifier, toolkit)

        # --- negative: onEvent raises on Create -> CREATE_FAILED -> ROLLBACK_COMPLETE ---
        fail_context = {
            "stack_name": fail_stack, "qualifier": qualifier, "marker": marker_fail,
            "param_name": param_fail, "force_fail": "true",
        }
        rc, out = _cdk(ctx, work, ["deploy", fail_stack, "--require-approval", "never"],
                       fail_context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
        assert rc != 0, (
            f"`cdk deploy` exited 0 for an app whose onEvent handler always raises on Create; "
            f"output tail: {out[-800:]!r}"
        )

        status = _poll_until(
            lambda: cfn.describe_stacks(StackName=fail_stack)["Stacks"][0]["StackStatus"],
            lambda s: s in ("ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_COMPLETE"),
            timeout_s=300.0, interval_s=5.0, description=f"terminal status for {fail_stack}",
        )
        assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

        events = _stack_events(cfn, fail_stack)
        observed = [(e["LogicalResourceId"], e.get("ResourceType"), e["ResourceStatus"])
                    for e in events]
        widget_failed = next(
            (e for e in events
             if e["LogicalResourceId"] == "Widget" and e["ResourceStatus"] == "CREATE_FAILED"),
            None,
        )
        assert widget_failed is not None, (
            f"no CREATE_FAILED event for Widget in {fail_stack}; events: {observed!r}"
        )
        on_event_created = next(
            (e for e in events
             if e["LogicalResourceId"].startswith("OnEvent")
             and e.get("ResourceType") == "AWS::Lambda::Function"
             and e["ResourceStatus"] == "CREATE_COMPLETE"),
            None,
        )
        assert on_event_created is not None, (
            f"no CREATE_COMPLETE event for the OnEvent function in {fail_stack}; "
            f"events: {observed!r}"
        )
        fn_name = on_event_created["PhysicalResourceId"]
        reason = widget_failed.get("ResourceStatusReason") or ""
        reason_lines = reason.split("\n")
        expected_head = [
            "Received response status [FAILED] from custom resource. Message returned: "
            f"Error: sim2real-onevent-failure-{marker_fail}",
            "", f"Logs: /aws/lambda/{fn_name}", "",
        ]
        assert reason_lines[:4] == expected_head, (
            f"Widget's CREATE_FAILED reason opened with {reason_lines[:4]!r}, expected "
            f"{expected_head!r}"
        )

        code, message = _error(lambda: ssm.get_parameter(Name=param_fail))
        assert code == "ParameterNotFound", (
            f"expected the parameter the handler never reached PutParameter for to be absent, "
            f"got error code {code!r} reading {param_fail!r}"
        )
        assert message == "", f"expected an empty message with ParameterNotFound, got {message!r}"

        # The rollback deleted every function the failed create made.
        lam = ctx.client("lambda")
        partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
        rolled_back_fns = _lambda_function_names(events)
        assert fn_name in rolled_back_fns, (
            f"expected {fn_name!r} among the stack's created functions, got {rolled_back_fns!r}"
        )
        for fn in rolled_back_fns:
            code, message = _error(lambda fn=fn: lam.get_function(FunctionName=fn))
            expected = ("Function not found: "
                        f"arn:{partition}:lambda:{ctx.region}:{ctx.account}:function:{fn}")
            assert (code, message) == ("ResourceNotFoundException", expected), (
                f"after ROLLBACK_COMPLETE, GetFunction {fn!r} returned ({code!r}, {message!r}), "
                f"expected ('ResourceNotFoundException', {expected!r})"
            )

        # --- positive control: identical app, not forced to fail -> CREATE_COMPLETE, parameter set ---
        ok_context = {
            "stack_name": ok_stack, "qualifier": qualifier, "marker": marker_ok,
            "param_name": param_ok, "force_fail": "false",
        }
        _cdk(ctx, work, ["deploy", ok_stack, "--require-approval", "never"], ok_context,
             timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

        ok_status = cfn.describe_stacks(StackName=ok_stack)["Stacks"][0]["StackStatus"]
        assert ok_status == "CREATE_COMPLETE", (
            f"positive control expected CREATE_COMPLETE, got {ok_status!r}"
        )
        written = ssm.get_parameter(Name=param_ok)["Parameter"]["Value"]
        assert written == marker_ok, (
            f"positive control: parameter {param_ok!r} held {written!r}, expected {marker_ok!r}"
        )
    finally:
        _teardown(ctx, [fail_stack, ok_stack], toolkit, qualifier, [param_fail, param_ok])


# ===== helpers =====


def _error(fn) -> tuple[str, str]:
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_parameter(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _stack_events(cfn, stack: str) -> list[dict]:
    """Every event of ``stack``, newest first, across all pages."""
    return [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack)
            for e in page["StackEvents"]]


def _lambda_function_names(events: list[dict]) -> list[str]:
    """Every Lambda function name a CloudFormation stack's events created."""
    return sorted({
        e["PhysicalResourceId"] for e in events
        if e.get("ResourceType") == "AWS::Lambda::Function" and e["ResourceStatus"] == "CREATE_COMPLETE"
    })


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered log stream can flush after the function's own delete and recreate the group.
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
                    f"log group {name!r} still present after {budget_s}s of deletes"
                )
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0,
                description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), f"the CDK app this check references is missing: {source}"
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns("cdk.out", "__pycache__"))
    return staged


def _bootstrap(ctx, qualifier: str, toolkit: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    cmd = [
        "cdk", "bootstrap", f"aws://{acct}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci", "--no-notices",
        "--tags", f"sim2real={CHECK}",
    ]
    r = subprocess.run(cmd, cwd=scratch, env=ctx.subprocess_env(), capture_output=True, text=True,
                       timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {r.returncode}: "
        f"{(r.stdout + r.stderr)[-1000:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color",
           "--app", f"{sys.executable} app.py"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    acct = ctx.client("sts").get_caller_identity()["Account"]
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_ACCOUNT"] = acct
    env["CDK_DEFAULT_REGION"] = ctx.region
    cmd += ["--context", f"account={acct}", "--context", f"region={ctx.region}"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    out = r.stdout + r.stderr
    if expect_rc is not None:
        assert r.returncode == expect_rc, (
            f"`cdk {args[0]}` exited {r.returncode}, expected {expect_rc}: {out[-1200:]!r}"
        )
    return r.returncode, out


def _stack_missing(exc: ClientError, stack: str) -> bool:
    """CloudFormation's own answer for a stack that does not exist; anything else is an error."""
    err = exc.response["Error"]
    return (err["Code"] == "ValidationError"
            and f"Stack with id {stack} does not exist" in err.get("Message", ""))


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if _stack_missing(exc, stack):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_missing(exc, stack):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _teardown(ctx, app_stacks: list[str], toolkit: str, qualifier: str,
              params: list[str]) -> None:
    """Delete the app stacks, their log groups and parameters, then bootstrap, and confirm it.

    Bootstrap stays while an app stack may remain, since its role is what deletes that stack.
    Called from run()'s finally: when the body failed, the residue is noted on that error.
    """
    found = sys.exc_info()[1]  # the body's failure in flight, if any
    errors: list[str] = []
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    acct = ctx.client("sts").get_caller_identity()["Account"]
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    ecr_repo = f"cdk-{qualifier}-container-assets-{acct}-{ctx.region}"
    cfn = ctx.client("cloudformation")

    # Read each stack's functions before its delete: every function a deploy ran wrote a
    # /aws/lambda/<function> log group that outlives the stack.
    lambda_fns: set[str] = set()
    stacks_gone = True

    def collect(s: str) -> None:
        try:
            lambda_fns.update(_lambda_function_names(_stack_events(cfn, s)))
        except ClientError as exc:
            if not _stack_missing(exc, s):
                raise

    def steps():
        """(label, step, is an app stack delete), generated lazily so each step sees the last."""
        for s in app_stacks:
            yield f"functions of app stack {s}", lambda s=s: collect(s), False
            yield f"app stack {s}", lambda s=s: _delete_stack_and_wait(
                ctx, s, timeout_s=max(30.0, deadline - time.monotonic())), True
        # After the stack delete: the function's own delete leaves its log group behind, and a
        # buffered flush can recreate it even after a first delete_log_group.
        for fn in sorted(lambda_fns):
            yield f"log group of {fn}", lambda fn=fn: _reap_log_group(
                ctx.client("logs"), f"/aws/lambda/{fn}"), False
        for p in params:
            yield f"parameter {p}", lambda p=p: _delete_parameter(ctx.client("ssm"), p), False
        if stacks_gone:
            yield f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging), False
            yield f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(
                ctx, toolkit, timeout_s=max(30.0, deadline - time.monotonic())), False

    # Run every step, then raise naming each failure.
    for label, step, is_app_stack in steps():
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — collected and raised below
            errors.append(f"{label}: {exc!r}")
            stacks_gone = stacks_gone and not is_app_stack

    if not stacks_gone:
        errors.append(f"toolkit stack {toolkit} kept: an app stack delete did not complete")
    else:
        remaining = _bootstrap_remnants(ctx, staging, ecr_repo, qualifier)
        while remaining and time.monotonic() < deadline:
            time.sleep(5.0)
            remaining = _bootstrap_remnants(ctx, staging, ecr_repo, qualifier)
        if remaining:
            errors.append(f"bootstrap remnants still present after {_TEARDOWN_DEADLINE_S}s: "
                          f"{remaining!r}")
    if errors and found is None:
        raise AssertionError("teardown left residue: " + "; ".join(errors))
    if errors:
        found.add_note("teardown left residue: " + "; ".join(errors))


def _bootstrap_remnants(ctx, staging: str, ecr_repo: str, qualifier: str) -> list[str]:
    remaining: list[str] = []
    try:
        ctx.client("s3").head_bucket(Bucket=staging)
        remaining.append(f"staging bucket {staging}")
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
    roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate()
             for r in page["Roles"] if r["RoleName"].startswith(f"cdk-{qualifier}-")]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
