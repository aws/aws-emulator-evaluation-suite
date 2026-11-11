"""durable-execution-server-managed-append-only-history."""

from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "durable-execution-server-managed-append-only-history"
GROUP = 'errors'
SERVICES = ['lambda']

DURABLE_RUNTIME = "python3.13"

# A durable-function handler: one checkpointed step, then a plain return.
DURABLE_HANDLER = """
from aws_durable_execution_sdk_python import durable_execution, durable_step


@durable_step
def do_step(step_context, value):
    return {"value": value, "done": True}


@durable_execution
def handler(event, context):
    result = context.step(do_step(event.get("value", "x")))
    return {"result": result}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        "expected CheckpointDurableExecution with a checkpoint token that is not the current, "
        f"authoritative one to be rejected, but it succeeded and returned {result!r} — "
        "history would be rewritable out of band"
    )


def _durable_role_arn(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-durable-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _cleanup():
        for pa in ("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                   "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy"):
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

    ctx.on_cleanup(_cleanup)
    for pa in ("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
               "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy"):
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=pa)
        except ClientError:
            pass
    return arn


def _create_durable_function_with_retry(lam, **kwargs):
    """CreateFunction answers InvalidParameterValueException until a fresh role is assumable;
    retry only that code on a deadline, since anything else is a real rejection."""
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                last_err = exc
                time.sleep(2.0)
                continue
            raise AssertionError(
                f"durable execution not usable in this account/region/SDK: {exc}"
            ) from None
    raise AssertionError(
        f"role {kwargs.get('Role')} still not assumable by lambda.amazonaws.com after 60s "
        f"(IAM propagation): {last_err}"
    )


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An out-of-band CheckpointDurableExecution call with a non-current checkpoint token is
    rejected, and GetDurableExecutionHistory is unchanged: the history is server-managed.
    """
    lam = ctx.client("lambda")
    role_arn = _durable_role_arn(ctx)
    fn = ctx.unique_name("sim2real-behav-durable-fn-")
    _create_durable_function_with_retry(
        lam,
        FunctionName=fn, Runtime=DURABLE_RUNTIME, Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _make_zip(DURABLE_HANDLER)}, Timeout=60, MemorySize=256,
        DurableConfig={"ExecutionTimeout": 300, "RetentionPeriodInDays": 1},
    )
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, fn))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))

    deadline = time.monotonic() + 90
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=fn)["State"]
        if state == "Active":
            break
        if state == "Failed":
            raise AssertionError(f"function {fn} entered Failed state while becoming active")
        time.sleep(2.0)
    else:
        raise AssertionError(f"function {fn} did not become Active within 90s (last state={state})")

    # Durable functions must be invoked via a QUALIFIED ARN pointing at a stable published version.
    version = lam.publish_version(FunctionName=fn)["Version"]

    resp = lam.invoke(
        FunctionName=fn, Qualifier=version,
        Payload=json.dumps({"value": "sim2real-behav-durable"}).encode("utf-8"),
    )
    assert resp["StatusCode"] == 200, resp
    decoded = json.loads(resp["Payload"].read())
    assert decoded["result"]["value"] == "sim2real-behav-durable", decoded

    arn = resp.get("DurableExecutionArn")
    if not arn:
        raise AssertionError("Invoke did not return a DurableExecutionArn; durable execution not usable here")

    before = lam.get_durable_execution_history(DurableExecutionArn=arn)
    events_before = before.get("Events", [])
    assert len(events_before) >= 1, (
        f"expected at least one recorded history event for a completed durable execution, got {before}"
    )

    bogus_token = base64.b64encode(b"sim2real-behav-not-the-real-token").decode("ascii")
    code, msg = _client_error(
        lambda: lam.checkpoint_durable_execution(DurableExecutionArn=arn, CheckpointToken=bogus_token)
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a stale/invalid checkpoint token, got {code}"
    )
    assert msg == "Invalid checkpoint token", f"invalid checkpoint token message: {msg!r}"

    after = lam.get_durable_execution_history(DurableExecutionArn=arn)
    events_after = after.get("Events", [])
    assert events_after == events_before, (
        f"a rejected CheckpointDurableExecution call must not rewrite or remove prior history entries; "
        f"before={events_before!r} after={events_after!r}"
    )


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on first invocation. Late log delivery can recreate it,
    so it must stay absent across two reads 5 s apart; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not present():
            time.sleep(5.0)
            if not present():
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
