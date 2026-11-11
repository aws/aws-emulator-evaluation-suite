"""invalid-parameter-rejection-on-writes."""

from __future__ import annotations

import json as _json

import io
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "invalid-parameter-rejection-on-writes"
GROUP = 'concurrency'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLES: dict = {}


def _role_arn(ctx):
    """Create this check's own Lambda execution role once per run and register its cleanup."""
    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = err.get("Code") == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", "")
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


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


def _deploy_function(ctx, lam, code, *, name=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because a
    target that accepts a call real AWS refuses must surface its actual response."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reserved/provisioned concurrency requests far beyond the account's concurrency pool are
    rejected with InvalidParameterValueException; a reasonable value is accepted, proving the
    rejection is about the absurd value and not concurrency features being unusable in this account.
    """
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, HANDLER_V1)

    settings = lam.get_account_settings()
    account_limit = settings["AccountLimit"]["ConcurrentExecutions"]
    unreserved = settings["AccountLimit"]["UnreservedConcurrentExecutions"]
    absurd = account_limit + 10_000_000

    reserved_code, _reserved_message = _error(
        lambda: lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=absurd)
    )
    assert reserved_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for reserved concurrency {absurd} "
        f"(account limit {account_limit}), got {reserved_code}"
    )
    # message varies: it quotes the account's minimum unreserved-concurrency floor, a value
    # derived from the account's concurrency quota that no API returns.

    # Independent read: the rejected reservation must not have taken effect.
    after_reserved_reject = lam.get_function_concurrency(FunctionName=fn)
    assert "ReservedConcurrentExecutions" not in after_reserved_reject, (
        f"rejected reservation of {absurd} was applied anyway: {after_reserved_reject}"
    )

    v1 = lam.publish_version(FunctionName=fn)["Version"]
    provisioned_code, provisioned_message = _error(
        lambda: lam.put_provisioned_concurrency_config(
            FunctionName=fn, Qualifier=v1, ProvisionedConcurrentExecutions=absurd
        )
    )
    assert provisioned_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for provisioned concurrency {absurd}, got {provisioned_code}"
    )
    assert provisioned_message == (
        f"Specified ConcurrentExecutions for function is greater than account's unreserved "
        f"concurrency [{unreserved}]."
    ), provisioned_message

    # Independent read: the rejected provisioned-concurrency config must not exist.
    provisioned_absent, absent_message = _error(
        lambda: lam.get_provisioned_concurrency_config(FunctionName=fn, Qualifier=v1)
    )
    assert provisioned_absent == "ProvisionedConcurrencyConfigNotFoundException", (
        f"rejected provisioned concurrency {absurd} left a config behind, got {provisioned_absent}"
    )
    assert absent_message == "No Provisioned Concurrency Config found for this function", absent_message

    # Positive control: a reasonable value is accepted, and independently observable —
    # proving the rejections above are about the absurd value, not concurrency writes
    # being unusable in this account.
    lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=1)
    confirmed = lam.get_function_concurrency(FunctionName=fn)
    assert confirmed.get("ReservedConcurrentExecutions") == 1, (
        f"expected reserved concurrency 1 to read back independently, got {confirmed}"
    )

    lam.delete_function_concurrency(FunctionName=fn)
    cleared = lam.get_function_concurrency(FunctionName=fn)
    assert "ReservedConcurrentExecutions" not in cleared, (
        f"delete_function_concurrency did not clear the value: {cleared}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
