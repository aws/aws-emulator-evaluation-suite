"""env-vars-and-module-state-isolated-between-two-distinct-functions."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'env-vars-and-module-state-isolated-between-two-distinct-functions'
GROUP = 'python-runtime'
SERVICES = ['lambda']

_HANDLER = """\
import os
import uuid

INIT_ID = str(uuid.uuid4())


def handler(event, context):
    return {
        "custom": os.environ.get("MY_VAR"),
        "only_a": os.environ.get("SIM2REAL_ONLY_A"),
        "only_b": os.environ.get("SIM2REAL_ONLY_B"),
        "fn_name_env": os.environ.get("AWS_LAMBDA_FUNCTION_NAME"),
        "init_id": INIT_ID,
    }
"""


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _role_arn(ctx) -> str:
    """An execution role this check creates and deletes in cleanup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    policy = f"arn:{arn.split(':')[1]}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity"))
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _cleanup_fn(lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered log stream can flush and recreate the group after delete_function returns, so
    one delete is one round, not a teardown.
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
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _wait_active(lam, fn, timeout_s=60):
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


def _invoke_sync(lam, fn, payload):
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse", Payload=json.dumps(payload).encode(),
    )
    body = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(
            f"Function {fn} returned FunctionError={resp['FunctionError']}: {body.decode()[:500]}"
        )
    return json.loads(body) if body else None


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two distinct functions each see only their own configured env vars (a key only one
    defines is absent in the other), their own AWS_LAMBDA_FUNCTION_NAME and their own
    module-scope init state.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    lam = ctx.client("lambda")
    role = _role_arn(ctx)
    code = _make_zip(_HANDLER)

    fn_a = ctx.unique_name("sim2real-behav-envsio-a-")
    fn_b = ctx.unique_name("sim2real-behav-envsio-b-")
    envs = (
        (fn_a, {"MY_VAR": "value-for-a", "SIM2REAL_ONLY_A": "a-only"}),
        (fn_b, {"MY_VAR": "value-for-b", "SIM2REAL_ONLY_B": "b-only"}),
    )
    for name, variables in envs:
        # Registered before create_function, so LIFO reaps the log group after the function
        # itself is deleted.
        ctx.on_cleanup(lambda name=name: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
        _create_function(
            lam, FunctionName=name, Runtime="python3.13", Handler="index.handler", Role=role,
            Code={"ZipFile": code}, MemorySize=128, Timeout=15,
            Environment={"Variables": variables}, Tags={"sim2real": CHECK},
        )
        ctx.on_cleanup(lambda name=name: _cleanup_fn(lam, name))
        _wait_active(lam, name)

    got_a = _invoke_sync(lam, fn_a, {})
    got_b = _invoke_sync(lam, fn_b, {})

    assert got_a["custom"] == "value-for-a", (
        f"{fn_a}: expected MY_VAR='value-for-a', got {got_a['custom']!r}"
    )
    assert got_b["custom"] == "value-for-b", (
        f"{fn_b}: expected MY_VAR='value-for-b', got {got_b['custom']!r}"
    )
    assert (got_a["only_a"], got_a["only_b"]) == ("a-only", None), (
        f"{fn_a}: expected its own SIM2REAL_ONLY_A='a-only' and no SIM2REAL_ONLY_B, got "
        f"{got_a['only_a']!r} / {got_a['only_b']!r}"
    )
    assert (got_b["only_b"], got_b["only_a"]) == ("b-only", None), (
        f"{fn_b}: expected its own SIM2REAL_ONLY_B='b-only' and no SIM2REAL_ONLY_A, got "
        f"{got_b['only_b']!r} / {got_b['only_a']!r}"
    )
    assert got_a["fn_name_env"] == fn_a, (
        f"{fn_a}: AWS_LAMBDA_FUNCTION_NAME was {got_a['fn_name_env']!r}, expected {fn_a!r}"
    )
    assert got_b["fn_name_env"] == fn_b, (
        f"{fn_b}: AWS_LAMBDA_FUNCTION_NAME was {got_b['fn_name_env']!r}, expected {fn_b!r}"
    )
    assert got_a["init_id"] != got_b["init_id"], (
        f"both functions report the same module-scope INIT_ID {got_a['init_id']!r} — their "
        f"init phases ran in a shared execution environment instead of isolated ones"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
