"""timeout-enforcement."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError, ReadTimeoutError

from behavioral_harness import tags


CHECK = "timeout-enforcement"
GROUP = 'compute'
SERVICES = ['lambda']
_TIMEOUT_S = 3
#: Bounded wait for the function to become Active.
POLL_BUDGET_S = 180.0
#: The handler sleeps far past Timeout so only a real kill can end the invoke early.
_HANDLER_SLEEP_S = 60
#: The timed-out invoke's read timeout: past Timeout, short of the handler's own sleep.
_READ_TIMEOUT_S = _TIMEOUT_S + 30


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}


def _exec_role_arn(ctx) -> str:
    """An execution role this check creates (once per run) and deletes in cleanup."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = f"arn:{_partition(ctx)}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    _ROLES[id(ctx)] = arn
    return arn


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _create_function_when_role_ready(lam, **kwargs):
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


def _cleanup_fn(ctx, lam, name):
    """Teardown; only the service's own not-found (ResourceNotFoundException) is tolerated."""
    for fn in (
        lambda: lam.delete_function_url_config(FunctionName=name),
        lambda: lam.delete_function(FunctionName=name),
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"),
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise


def _wait_active(lam, fn, timeout_s=POLL_BUDGET_S):
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


def _deploy_function(ctx, lam, code, *, name=None, handler="index.handler",
                     runtime="python3.12", memory=128, timeout=30, environment=None,
                     layers=None, ephemeral_storage=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or _exec_role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
        "Tags": {"sim2real:managed": "true"},
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_function_when_role_ready(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


# timing:real-time — workflow: 3 s https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html
@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A function that exceeds Timeout is killed near the declared bound; one that stays under it is not."""
    lam = ctx.client("lambda")
    code = """\
import time
def handler(event, context):
    if event.get("sleep"):
        time.sleep(%d)
    return {"should": "never reach" if event.get("sleep") else "ok"}
""" % _HANDLER_SLEEP_S
    fn = _deploy_function(ctx, lam, code, timeout=_TIMEOUT_S)

    control = lam.invoke(FunctionName=fn, Payload=json.dumps({"sleep": False}).encode())
    assert control.get("FunctionError") is None, (
        f"positive control: expected no FunctionError for a quick invoke, got {control.get('FunctionError')!r}"
    )
    control_body = json.loads(control["Payload"].read())
    assert control_body.get("should") == "ok", (
        f"positive control: expected {{'should': 'ok'}}, got {control_body!r}"
    )

    # No retry and a read timeout short of the sleep: a target that never kills the function
    # fails here instead of running into the harness deadline.
    killer = ctx.client("lambda", config=Config(read_timeout=_READ_TIMEOUT_S, retries={"max_attempts": 0}))
    start = time.monotonic()
    try:
        resp = killer.invoke(FunctionName=fn, Payload=json.dumps({"sleep": True}).encode())
    except ReadTimeoutError as exc:
        raise AssertionError(
            f"the invoke of a sleep({_HANDLER_SLEEP_S}) handler with Timeout={_TIMEOUT_S} had not "
            f"returned after {_READ_TIMEOUT_S}s: the function was not killed at its Timeout"
        ) from exc
    elapsed = time.monotonic() - start
    assert resp.get("FunctionError") == "Unhandled", (
        f"expected FunctionError 'Unhandled' after a sleep({_HANDLER_SLEEP_S}) invoke against "
        f"Timeout={_TIMEOUT_S}, got {resp.get('FunctionError')!r}"
    )
    body = json.loads(resp["Payload"].read())
    # The payload's errorType differs across runtime generations, so only its message is graded.
    assert (body.get("errorMessage") or "").strip(), f"expected a non-empty errorMessage, got {body!r}"
    # Causal bounds, not a performance bound: the kill cannot land before the declared Timeout,
    # and landing after the handler's own sleep would mean the handler was never killed.
    assert _TIMEOUT_S <= elapsed < _HANDLER_SLEEP_S, (
        f"expected the kill between the declared Timeout={_TIMEOUT_S}s and the handler's own "
        f"{_HANDLER_SLEEP_S}s sleep, measured elapsed={elapsed:.1f}s"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
