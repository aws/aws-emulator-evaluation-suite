"""function-error-unhandled."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "function-error-unhandled"
GROUP = 'invoke_sync'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_EXEC_ROLES: dict = {}


def _exec_role_arn(ctx):
    """Execution role this check creates for its functions, once per run."""
    cached = _EXEC_ROLES.get(id(ctx))
    if cached and cached[0] is ctx:
        return cached[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _EXEC_ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function_retrying(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role propagates to Lambda."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            err = e.response.get("Error", {})
            if (err.get("Code") == "InvalidParameterValueException"
                    and "cannot be assumed by Lambda" in err.get("Message", "")
                    and time.monotonic() < deadline):
                time.sleep(3)
                continue
            raise


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


def _create_function(ctx, lam, code):
    name = ctx.unique_name("sim2real-behav-fn-")
    _create_function_retrying(lam,
        FunctionName=name, Runtime="python3.12", Handler="index.handler",
        Role=_exec_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    return name


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unhandled exception → FunctionError=Unhandled + a payload naming the real exception."""
    lam = ctx.client("lambda")
    nonce = ctx.unique_name("boom-")
    fn = _create_function(ctx, lam, f"def handler(event, context): raise ValueError({nonce!r})\n")
    _wait_active(lam, fn)

    resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    assert resp["StatusCode"] == 200, f"expected HTTP 200 even on function error, got {resp['StatusCode']}"
    assert resp["FunctionError"] == "Unhandled", (
        f"expected X-Amz-Function-Error: Unhandled, got {resp.get('FunctionError')!r}"
    )
    body = json.loads(resp["Payload"].read())
    assert body.get("errorType") == "ValueError", (
        f"errorType must name the real exception class, got {body!r}"
    )
    assert body.get("errorMessage") == nonce, (
        f"errorMessage must be the exception's own message ({nonce!r}), got {body!r}"
    )
    trace = body.get("stackTrace")
    assert isinstance(trace, list) and len(trace) > 0 and all(isinstance(f, str) for f in trace), (
        f"stackTrace must be a non-empty list of frame strings, got {trace!r}"
    )
    assert any("handler" in f for f in trace), (
        f"stackTrace must include the frame that raised, got {trace!r}"
    )

    # Deterministic: a second invoke fails identically rather than being cached into success.
    again = lam.invoke(FunctionName=fn, Payload=b"{}")
    assert again["FunctionError"] == "Unhandled", (
        f"the failure must reproduce on every invoke, second invoke gave "
        f"FunctionError={again.get('FunctionError')!r}"
    )
    again_body = json.loads(again["Payload"].read())
    assert again_body.get("errorMessage") == nonce, (
        f"second invoke's errorMessage was {again_body.get('errorMessage')!r}, expected the same {nonce!r}"
    )

    # Positive control on the same runtime: a function that does not raise reports no FunctionError
    # at all — without this, a stub that hardcodes FunctionError=Unhandled would still pass above.
    good = _create_function(ctx, lam, "def handler(event, context): return {'ok': True}\n")
    _wait_active(lam, good)
    ok = lam.invoke(FunctionName=good, Payload=b"{}")
    assert ok["StatusCode"] == 200, ok["StatusCode"]
    assert "FunctionError" not in ok, (
        f"the control function must not report a FunctionError, got {ok.get('FunctionError')!r}"
    )
    assert json.loads(ok["Payload"].read()) == {"ok": True}, "the control function's own return value must pass through"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
