"""durable-execution-checkpoint-ttl-bound."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "durable-execution-checkpoint-ttl-bound"
GROUP = 'durable_execution'
SERVICES = ['lambda']

DURABLE_RUNTIME = "python3.13"
DURABLE_HANDLER_ENTRY = "lambda_function.lambda_handler"

DURABLE_MANAGED_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

DURABLE_HANDLER_SRC = """
from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
    durable_step,
)
from aws_durable_execution_sdk_python.config import Duration


@durable_step
def step_one(step_context, n):
    return {"step": "one", "n": n}


@durable_step
def step_two(step_context, n):
    return {"step": "two", "n": n}


@durable_step
def step_three(step_context, n):
    return {"step": "three", "n": n}


@durable_execution
def lambda_handler(event, context: DurableContext):
    n = event.get("n", 0)
    wait_seconds = event.get("wait_seconds", 0)

    r1 = context.step(step_one(n))
    if wait_seconds:
        context.wait(Duration.from_seconds(wait_seconds))
    r2 = context.step(step_two(n))
    r3 = context.step(step_three(n))

    return {"r1": r1, "r2": r2, "r3": r3}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_url_config(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _get_execution_tolerant(lam, arn):
    try:
        return lam.get_durable_execution(DurableExecutionArn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_with_role_retry(fn, timeout_s=90, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if "does not have permissions" in str(exc) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _durable_role_arn(ctx, *, sqs_send=False):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-durrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]

    def _cleanup_role():
        for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for pa in DURABLE_MANAGED_POLICIES:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pa)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    for pa in DURABLE_MANAGED_POLICIES:
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=pa)
        except ClientError:
            pass
    if sqs_send:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="sqs-send",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["sqs:SendMessage", "sqs:GetQueueAttributes"],
                    "Resource": "*",
                }],
            }),
        )
    time.sleep(12)
    return arn


def _create_durable_function(ctx, lam, handler_source, *, execution_timeout=600,
                             retention_period_days=7, sqs_send=False):
    name = ctx.unique_name("sim2real-behav-durfn-")
    role_arn = _durable_role_arn(ctx, sqs_send=sqs_send)

    def _create():
        return lam.create_function(
            FunctionName=name,
            Runtime=DURABLE_RUNTIME,
            Role=role_arn,
            Handler=DURABLE_HANDLER_ENTRY,
            Code={"ZipFile": _make_zip(handler_source, "lambda_function.py")},
            Timeout=120,
            MemorySize=128,
            DurableConfig={
                "ExecutionTimeout": execution_timeout,
                "RetentionPeriodInDays": retention_period_days,
            },
        )

    _create_with_role_retry(_create)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name, timeout_s=120)
    return name


def _start_durable_execution(ctx, lam, function_name, qualifier, payload, *, invocation_type="Event"):
    execution_name = ctx.unique_name("sim2real-behav-durex-")
    resp = lam.invoke(
        FunctionName=function_name,
        Qualifier=qualifier,
        InvocationType=invocation_type,
        DurableExecutionName=execution_name,
        Payload=json.dumps(payload).encode("utf-8"),
    )
    arn = resp.get("DurableExecutionArn")
    if not arn:
        found = _poll_until(
            lambda: lam.list_durable_executions_by_function(
                FunctionName=function_name, Qualifier=qualifier, DurableExecutionName=execution_name
            ),
            lambda r: len(r.get("DurableExecutions", [])) > 0,
            timeout_s=30,
            interval_s=2.0,
            description=f"durable execution {execution_name} to be listed",
        )
        arn = found["DurableExecutions"][0]["DurableExecutionArn"]
    return resp, arn, execution_name


# timing:real-time — workflow: 30 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Checkpoints/waits beyond the execution's configured TTL force a terminal (stopped) state.

    Raises AssertionError (never skips) when durable functions are not usable in the target
    account/region.
    """
    lam = ctx.client("lambda")
    try:
        fn = _create_durable_function(
            ctx, lam, DURABLE_HANDLER_SRC, execution_timeout=30, retention_period_days=1
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"durable functions not usable in this account/region: {exc}") from None
    v1 = lam.publish_version(FunctionName=fn)["Version"]

    started = time.monotonic()
    resp, arn, _ = _start_durable_execution(
        ctx, lam, fn, v1, {"n": 1, "wait_seconds": 120}, invocation_type="Event"
    )
    assert resp["StatusCode"] == 202, resp

    # GetDurableExecution can transiently 404 in the instant right after Invoke hands back the
    # ARN (observed on real AWS) — tolerate exactly that one code while polling for RUNNING, and
    # nothing else.
    running = _poll_until(
        lambda: _get_execution_tolerant(lam, arn),
        lambda r: r is not None and r.get("Status") == "RUNNING",
        timeout_s=30,
        interval_s=2.0,
        description=f"durable execution {arn} reach RUNNING",
    )
    assert running is not None and running["Status"] == "RUNNING", running

    # The execution's own 30s ExecutionTimeout is well below its 120s in-flight wait — it must be
    # forced out of RUNNING once that TTL elapses, without the check ever calling Stop itself.
    terminal = _poll_until(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn),
        lambda r: r.get("Status") in ("FAILED", "STOPPED", "SUCCEEDED", "TIMED_OUT"),
        timeout_s=120,
        interval_s=3.0,
        description=f"durable execution {arn} to be forced out of RUNNING by its execution TTL",
    )
    elapsed = time.monotonic() - started
    assert terminal["Status"] in ("FAILED", "STOPPED", "TIMED_OUT"), (
        f"expected the execution to be forced into a non-success terminal state by its own TTL, got {terminal}"
    )
    # Two-sided clock: the 30s ExecutionTimeout must be what forced this, not the 120s in-flight
    # wait completing naturally (which would also leave RUNNING, just 90s+ later) and not some
    # unrelated fault firing implausibly fast.
    assert 15 <= elapsed < 100, (
        f"execution reached {terminal['Status']} in {elapsed:.1f}s; its own 30s ExecutionTimeout "
        f"should force it out well before the 120s in-flight wait would complete naturally, and "
        f"not implausibly fast"
    )

    # Post-terminal StopDurableExecution is a harmless idempotent no-op on real AWS.
    lam.stop_durable_execution(DurableExecutionArn=arn)
    after_stop = lam.get_durable_execution(DurableExecutionArn=arn)
    assert after_stop["Status"] != "RUNNING", after_stop


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
