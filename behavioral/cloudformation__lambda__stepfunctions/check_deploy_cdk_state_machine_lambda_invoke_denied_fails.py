"""deploy-cdk-state-machine-lambda-invoke-denied-fails."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-state-machine-lambda-invoke-denied-fails"
GROUP = "deploy-cdk"
SERVICES = ["cloudformation", "lambda", "stepfunctions"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_DENY_POLICY = "sim2real-deny-invoke"

_APP = "sfn_lambda_invoke"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An explicit Deny on the `cdk deploy`-granted state machine role fails the LambdaInvoke task
    with Lambda.AWSLambdaException naming the denied call, the function never runs, and removing
    the Deny lets the identical execution succeed.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/connect-lambda.html
    """
    require_tools("cdk")
    ctx.verify_account_safety()
    acct = ctx.account
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    logs = ctx.client("logs")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkdeny-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    context = {"account": acct, "region": ctx.region, "stack_name": stack,
               "qualifier": qualifier, "retry_service_exceptions": "false"}
    work = _stage_app(ctx, _APP)

    # Registered before bootstrap and deploy so a part-way failure still tears down; LIFO runs
    # the app stack (then its log group) first, while the toolkit's deploy role still exists.
    app_state: dict[str, str] = {}
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, staging))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, toolkit))
    ctx.on_cleanup(lambda: _teardown_app(ctx, logs, stack, app_state))

    _bootstrap(ctx, qualifier, toolkit)
    _cdk(ctx, work, ["deploy", stack], context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    outputs = _stack_outputs(cfn, stack)
    fn_name = outputs["FunctionName"]
    sm_arn = outputs["StateMachineArn"]
    role_name = outputs["RoleArn"].rsplit("/", 1)[-1]
    log_group = f"/aws/lambda/{fn_name}"
    app_state["log_group"] = log_group
    roles = _stack_physical_ids(cfn, stack, "AWS::IAM::Role")
    assert role_name in roles, f"the state machine role {role_name!r} is not in the stack's roles {roles!r}"

    def _run(marker: str) -> dict:
        execution = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("exec-"),
            input=json.dumps({"value": 1, "tag": marker}),
        )
        return _terminal(sfn, execution["executionArn"])

    # 1. Positive control: the auto-granted permission lets the task invoke the function.
    control_marker = ctx.unique_name("ctl-")
    control_start_ms = int(time.time() * 1000)
    start = time.monotonic()
    control = _run(control_marker)
    assert control["status"] == "SUCCEEDED", (
        f"positive control ended {control['status']!r}, expected SUCCEEDED "
        f"(error={control.get('error')!r}, cause={control.get('cause')!r})"
    )
    # The function logs each tag it is invoked with; the time until the control's line is
    # readable sizes the window that proves the denied tag never arrives.
    control_seen = _first_log_events_containing(logs, log_group, control_marker, control_start_ms)
    control_latency_s = time.monotonic() - start
    assert control_seen == [f"tag {control_marker}"], (
        f"the control invocation logged {control_seen!r}, expected its tag line"
    )

    # 2. Break exactly one thing: an explicit Deny on lambda:InvokeFunction for this role.
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_DENY_POLICY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "lambda:InvokeFunction", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, _DENY_POLICY))

    # 3. Negative: the identical shape of call, denied. IAM is eventually consistent, so retry on
    #    a transient still-allowed SUCCEEDED with a FRESH marker each attempt.
    deny_start_ms = int(time.time() * 1000)
    deadline = time.monotonic() + 90.0
    negative = None
    neg_marker = None
    while True:
        neg_marker = ctx.unique_name("deny-")
        negative = _run(neg_marker)
        if negative["status"] == "FAILED":
            break
        if time.monotonic() > deadline:
            raise AssertionError(
                f"the explicit Deny never took effect within 90s; last status "
                f"{negative['status']!r}"
            )
        time.sleep(2)
    assert negative["error"] == "Lambda.AWSLambdaException", (
        f"expected error Lambda.AWSLambdaException once lambda:InvokeFunction was denied, got "
        f"error={negative.get('error')!r} cause={negative.get('cause')!r}"
    )
    fn_arn = f"arn:aws:lambda:{ctx.region}:{acct}:function:{fn_name}"
    # The session name and request id are minted per call; every other part is graded exactly.
    want_cause = re.compile(
        re.escape(f"User: arn:aws:sts::{acct}:assumed-role/{role_name}/") + r"[A-Za-z0-9_+=,.@-]+"
        + re.escape(f" is not authorized to perform: lambda:InvokeFunction on resource: {fn_arn} "
                    "with an explicit deny in an identity-based policy (Service: Lambda, "
                    "Status Code: 403, Request ID: ")
        + r"[A-Za-z0-9-]+" + re.escape(") (SDK Attempt Count: 1)"))
    assert want_cause.fullmatch(negative.get("cause") or ""), (
        f"the denial's cause is {negative.get('cause')!r}, expected Lambda's AccessDeniedException "
        f"for {role_name!r} on {fn_arn!r} with an explicit deny"
    )

    # 4. Effect absent: the function must never have run for the denied marker, held over a
    #    window derived from the positive control's own measured latency.
    window_s = max(10.0, 3.0 * control_latency_s)
    seen = _log_events_containing(logs, log_group, neg_marker, deny_start_ms, window_s)
    assert seen == [], (
        f"the function logged {seen!r} for the denied marker {neg_marker!r} — the denied "
        f"invocation must never run"
    )

    # 5. Control: remove the Deny, the identical shape of call succeeds again.
    _delete_role_policy(iam, role_name, _DENY_POLICY)
    restored_marker = ctx.unique_name("restored-")
    restored = None
    deadline = time.monotonic() + 90.0
    while True:
        restored = _run(restored_marker)
        if restored["status"] == "SUCCEEDED":
            break
        if time.monotonic() > deadline:
            raise AssertionError(
                f"removing the Deny never restored success within 90s; last status "
                f"{restored['status']!r} (error={restored.get('error')!r})"
            )
        time.sleep(2)
    assert json.loads(restored["output"]) == {"doubled": 2, "echo": restored_marker}, (
        f"control after removing the Deny returned {restored.get('output')!r}"
    )

    # `cdk destroy` in-band is the graded teardown path.
    _cdk(ctx, work, ["destroy", stack, "--force"], context, timeout_s=_DEPLOY_TIMEOUT_S,
         expect_rc=0)

    stack_err = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert stack_err == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"DescribeStacks on {stack!r} after `cdk destroy` returned {stack_err!r}"
    )
    _reap_log_group(logs, log_group)
    lam_err = _error(lambda: lam.get_function(FunctionName=fn_name))
    assert lam_err == (
        "ResourceNotFoundException", f"Function not found: arn:aws:lambda:{ctx.region}:{acct}:function:{fn_name}"
    ), f"the destroyed function is still reachable through its own API: {lam_err!r}"
    sfn_err = _error(lambda: sfn.describe_state_machine(stateMachineArn=sm_arn))
    assert sfn_err == ("StateMachineDoesNotExist", f"State Machine Does Not Exist: '{sm_arn}'"), (
        f"the destroyed state machine is still reachable through its own API: {sfn_err!r}"
    )
    for role in roles:
        role_err = _error(lambda role=role: iam.get_role(RoleName=role))
        assert role_err == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
            f"GetRole on the destroyed execution role {role!r} returned {role_err!r}"
        )


# ===== helpers =====

def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) ``fn`` raises. Raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _terminal(sfn, execution_arn: str, *, timeout_s: float = 120.0) -> dict:
    """Poll DescribeExecution to any terminal status. Never asserts how long it took."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=execution_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2)
    raise AssertionError(f"{execution_arn} was still RUNNING after {timeout_s}s. Last describe: {last!r}")


def _log_events_containing(logs, log_group: str, needle: str, start_ms: int,
                           window_s: float) -> list[str]:
    """Every log line containing ``needle`` in ``log_group`` since ``start_ms``, polled for
    ``window_s`` so a late-arriving log is caught rather than missed by a single read."""
    deadline = time.monotonic() + window_s
    found: list[str] = []
    while True:
        try:
            events = logs.filter_log_events(
                logGroupName=log_group, startTime=start_ms, filterPattern=f'"{needle}"'
            )["events"]
            found = [e["message"] for e in events]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            found = []
        if time.monotonic() >= deadline:
            return found
        time.sleep(2.0)


def _first_log_events_containing(logs, log_group: str, needle: str, start_ms: int, *,
                                 timeout_s: float = 120.0) -> list[str]:
    """Poll until a log line containing ``needle`` is readable in ``log_group``; return them."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            events = logs.filter_log_events(
                logGroupName=log_group, startTime=start_ms, filterPattern=f'"{needle}"'
            )["events"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            events = []
        if events:
            return [e["message"].rstrip("\n") for e in events]
        if time.monotonic() >= deadline:
            raise AssertionError(f"no log line containing {needle!r} in {log_group!r} within {timeout_s}s")
        time.sleep(2.0)


def _delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _stack_outputs(cfn, stack: str) -> dict[str, str]:
    stacks = cfn.describe_stacks(StackName=stack)["Stacks"]
    assert len(stacks) == 1, f"expected one stack named {stack!r}, got {stacks!r}"
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _stack_physical_ids(cfn, stack: str, resource_type: str) -> list[str]:
    return sorted(r["PhysicalResourceId"]
                  for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
                  if r["ResourceType"] == resource_type)


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in exc.response["Error"].get("Message", ""):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        time.sleep(2.0)
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


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 2.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
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


def _bootstrap(ctx, qualifier: str, toolkit: str) -> None:
    ctx.verify_account_safety()
    acct = ctx.account
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    cmd = [
        "cdk", "bootstrap", f"aws://{acct}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit,
        "--ci", "--no-version-reporting", "--no-notices",
        "--tags", f"sim2real={CHECK}",
    ]
    r = subprocess.run(cmd, cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
                       timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    if args and args[0] == "deploy":
        cmd += ["--require-approval", "never"]
    r = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True, text=True,
                       timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete or missing"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _teardown_app(ctx, logs, stack: str, app_state: dict[str, str]) -> None:
    """Delete the app stack if `cdk destroy` did not, then the function's log group."""
    _delete_stack_and_wait(ctx, stack)
    if "log_group" in app_state:
        _reap_log_group(logs, app_state["log_group"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
