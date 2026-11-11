"""invoke-without-tenant-id-on-tenant-isolated-function-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-without-tenant-id-on-tenant-isolated-function-rejected"
GROUP = "tenant-isolation"
SERVICES = ["lambda"]

_HANDLER = """\
def handler(event, context):
    return {"ok": True}
"""

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 2.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; raise if not."""
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
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-tcy-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_active(ctx, lam, fn: str, timeout_s: float = 120.0) -> dict:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"{fn} failed to become Active: {last.get('StateReason')!r}")
        if last["State"] == "Active":
            return last
        time.sleep(2.0)
    raise TimeoutError(f"{fn} never became Active in {timeout_s:.0f}s; last={last!r}")


def _create(ctx, lam, role: str) -> str:
    fn = ctx.unique_name("sim2real-behav-tcy-")
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Role=role, Runtime="python3.13", Handler="index.handler",
                Code={"ZipFile": _zip({"index.py": _HANDLER})}, Timeout=10, MemorySize=128,
                TenancyConfig={"TenantIsolationMode": "PER_TENANT"},
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            if "cannot be assumed" not in exc.response["Error"].get("Message", ""):
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(f"the execution role was never assumable: {exc}") from exc
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    _wait_active(ctx, lam, fn)
    return fn


def _invoke_ok(lam, fn: str, tenant_id: str) -> None:
    resp = lam.invoke(FunctionName=fn, Payload=b"{}", TenantId=tenant_id)
    assert resp["StatusCode"] == 200 and resp.get("FunctionError") is None, (
        f"invoke with TenantId={tenant_id!r} must succeed; got status={resp['StatusCode']!r} "
        f"FunctionError={resp.get('FunctionError')!r}"
    )


def _error(fn) -> tuple:
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the invoke to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Invoking a function enabled with TenancyConfig TenantIsolationMode PER_TENANT, with no
    TenantId, is refused with InvalidParameterValueException and its exact message; a tenant-id'd
    invoke on the same function still succeeds, before and after.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/tenant-isolation-invoke.html
    """
    lam = ctx.client("lambda")
    fn = _create(ctx, lam, _role(ctx))

    # Positive control first: the function is reachable with a tenant id.
    _invoke_ok(lam, fn, "sim2real-tenant-blue")

    # The one broken thing: invoke the same function with no TenantId at all.
    code, message = _error(lambda: lam.invoke(FunctionName=fn, Payload=b"{}"))
    assert code == "InvalidParameterValueException", (
        f"invoke without a TenantId on a tenant-isolated function must be "
        f"InvalidParameterValueException, got {code!r}"
    )
    assert message == (
        "The invoked function is enabled with tenancy configuration. "
        "Add a valid tenant ID in your request and try again."
    ), f"unexpected message for the missing-tenant-id refusal: {message!r}"

    # And the control still works afterwards: the rejection did not disable the function.
    _invoke_ok(lam, fn, "sim2real-tenant-green")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
