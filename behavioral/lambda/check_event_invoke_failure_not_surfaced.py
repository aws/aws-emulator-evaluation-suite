"""event-invoke-failure-not-surfaced."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "event-invoke-failure-not-surfaced"
GROUP = 'invoke_async'
SERVICES = ['lambda']

RAISES = """\
def handler(event, context):
    raise RuntimeError("sim2real-intentional-async-failure")
"""

RETURNS = """\
def handler(event, context):
    return {"marker": "sim2real-async-ok"}
"""


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
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll(probe, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=120):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        return cfg if cfg["State"] == "Active" else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _deploy(ctx, lam, code):
    name = ctx.unique_name("sim2real-behav-fn-")
    _create_function_retrying(lam,
        FunctionName=name, Runtime="python3.12", Handler="index.handler",
        Role=_exec_role_arn(ctx), Code={"ZipFile": _make_zip(code)},
        MemorySize=128, Timeout=30,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(call):
    try:
        result = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A failing function's RequestResponse invoke surfaces FunctionError Unhandled and its errorType,
    while Event invokes of it and of a succeeding function return 202 with an empty body and no
    FunctionError; Event still refuses an unknown function and an unparseable body with exact messages."""
    lam = ctx.client("lambda")
    failing = _deploy(ctx, lam, RAISES)
    working = _deploy(ctx, lam, RETURNS)

    # RequestResponse surfaces the execution outcome.
    sync = lam.invoke(FunctionName=failing, InvocationType="RequestResponse", Payload=b"{}")
    assert sync["StatusCode"] == 200, sync["StatusCode"]
    assert sync.get("FunctionError") == "Unhandled", (
        f"a raising handler must set FunctionError=Unhandled on the sync path, got "
        f"{sync.get('FunctionError')!r}"
    )
    sync_body = json.loads(sync["Payload"].read())
    assert sync_body.get("errorType") == "RuntimeError", sync_body
    assert "sim2real-intentional-async-failure" in sync_body.get("errorMessage", ""), sync_body

    # Event does not: 202, empty payload, no FunctionError — for the identical function.
    ev = lam.invoke(FunctionName=failing, InvocationType="Event", Payload=b"{}")
    assert ev["StatusCode"] == 202, (
        f"Event invoke must be accepted with 202 regardless of the handler outcome, got "
        f"{ev['StatusCode']}"
    )
    assert "FunctionError" not in ev, (
        f"the async caller must never see the execution error, got FunctionError="
        f"{ev.get('FunctionError')!r}"
    )
    assert ev["Payload"].read() == b"", "an Event invoke must return an empty response body"

    # ... and the successful function's return value is equally discarded.
    ev_ok = lam.invoke(FunctionName=working, InvocationType="Event", Payload=b"{}")
    assert ev_ok["StatusCode"] == 202, ev_ok["StatusCode"]
    assert ev_ok["Payload"].read() == b"", (
        "an Event invoke must not return the handler's return value"
    )
    assert "FunctionError" not in ev_ok, ev_ok.get("FunctionError")

    # Request-time validation is still synchronous on the async path.
    absent = ctx.unique_name("sim2real-behav-absent-")
    nf_code, nf_msg = _error(
        lambda: lam.invoke(FunctionName=absent, InvocationType="Event", Payload=b"{}")
    )
    assert nf_code == "ResourceNotFoundException", (
        f"an Event invoke of an unknown function must fail synchronously with "
        f"ResourceNotFoundException, got {nf_code}"
    )
    expected_nf_msg = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{absent}"
    assert nf_msg == expected_nf_msg, (
        f"expected message {expected_nf_msg!r} invoking an unknown function, got {nf_msg!r}"
    )
    bad_code, bad_msg = _error(
        lambda: lam.invoke(FunctionName=working, InvocationType="Event", Payload=b"not-json")
    )
    assert bad_code == "InvalidRequestContentException", (
        f"an unparseable Event payload must be rejected synchronously with "
        f"InvalidRequestContentException, got {bad_code}: {bad_msg}"
    )
    expected_bad_msg = (
        "Could not parse request body into json: Could not parse payload into json: "
        "Unrecognized token 'not': was expecting (JSON String, Number, Array, Object or token "
        "'null', 'true' or 'false')\n at [Source: REDACTED "
        "(`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: 1]"
    )
    assert bad_msg == expected_bad_msg, (
        f"expected message {expected_bad_msg!r} for an unparseable payload, got {bad_msg!r}"
    )

    # The control path still works after the negatives.
    final = lam.invoke(FunctionName=working, InvocationType="RequestResponse", Payload=b"{}")
    assert final["StatusCode"] == 200 and "FunctionError" not in final, final.get("FunctionError")
    final_body = json.loads(final["Payload"].read())
    assert final_body == {"marker": "sim2real-async-ok"}, (
        f"expected the working function's normal return value, got {final_body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
