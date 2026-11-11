"""provisioned-concurrency-is-capped-by-reserved-concurrency."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioned-concurrency-is-capped-by-reserved-concurrency"
GROUP = "concurrency"
SERVICES = ["lambda"]

_RESERVED = 4  # small and fixed; the check asserts the account can afford it before reserving
_HANDLER = 'def handler(event, context):\n    return {"ok": True}\n'


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Provisioned concurrency summed across versions may equal but never exceed the function's
    reserved concurrency, and the reservation cannot be lowered below the allocation.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/provisioned-concurrency.html
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    # The reservation must be affordable out of the pool the ACCOUNT reports, never a pinned quota.
    unreserved = lam.get_account_settings()["AccountLimit"]["UnreservedConcurrentExecutions"]
    assert unreserved >= _RESERVED + 100, (
        f"the account reports only {unreserved} unreserved concurrent executions, which is not "
        f"enough to reserve {_RESERVED} and still leave the 100 units AWS keeps for unreserved "
        f"functions — this check cannot run against a pool this squeezed"
    )

    role_arn = _create_execution_role(ctx, iam)
    fn = ctx.unique_name("sim2real-behav-pcpool-")
    _create_function(
        ctx,
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        MemorySize=128,
        Timeout=10,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    v1 = lam.publish_version(FunctionName=fn)["Version"]
    lam.update_function_configuration(FunctionName=fn, Description="second version")
    _wait_last_update_successful(lam, fn)
    v2 = lam.publish_version(FunctionName=fn)["Version"]
    assert v1 != v2, f"the two published versions must differ, both were {v1!r}"

    lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=_RESERVED)
    ctx.on_cleanup(lambda: lam.delete_function_concurrency(FunctionName=fn))
    reserved = lam.get_function_concurrency(FunctionName=fn)["ReservedConcurrentExecutions"]
    assert reserved == _RESERVED, (
        f"GetFunctionConcurrency must report the reservation just made: expected {_RESERVED}, got "
        f"{reserved}"
    )

    # ---- beat 1: positive control — half the reservation is allocatable to one version ----
    half = reserved // 2
    lam.put_provisioned_concurrency_config(
        FunctionName=fn, Qualifier=v1, ProvisionedConcurrentExecutions=half
    )
    ctx.on_cleanup(
        lambda: lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=v1)
    )
    ready_v1 = _wait_pc_ready(lam, fn, v1)
    assert ready_v1["AllocatedProvisionedConcurrentExecutions"] == half, (
        f"version {v1} must end up with exactly {half} allocated provisioned executions, "
        f"GetProvisionedConcurrencyConfig reports {ready_v1!r}"
    )

    # ---- beats 2-3: break exactly one thing — ask the other version for one unit too many ----
    over = reserved - half + 1
    err = _client_error(
        lambda: lam.put_provisioned_concurrency_config(
            FunctionName=fn, Qualifier=v2, ProvisionedConcurrentExecutions=over
        )
    )
    assert err.get("Code") == "InvalidParameterValueException", (
        f"allocating {over} provisioned executions to version {v2} would take the function's total "
        f"to {half + over}, above its reserved concurrency of {reserved}, so it must be refused "
        f"with InvalidParameterValueException; got {err.get('Code')!r}: {err.get('Message')!r}"
    )
    assert err.get("Message") == "Requested Provisioned Concurrency should not be greater than the reservedConcurrentExecution for function", f"expected the exact over-allocation message, got {err.get('Message')!r}"

    # ---- beat 4: effect absent — no config was created for v2, by an independent read ----
    missing = _client_error(
        lambda: lam.get_provisioned_concurrency_config(FunctionName=fn, Qualifier=v2)
    )
    assert missing.get("Code") == "ProvisionedConcurrencyConfigNotFoundException", (
        f"the refused allocation must leave version {v2} with no provisioned concurrency config; "
        f"GetProvisionedConcurrencyConfig answered {missing.get('Code')!r}"
    )
    assert missing.get("Message") == "No Provisioned Concurrency Config found for this function", f"expected the exact not-found message, got {missing.get('Message')!r}"
    listed = lam.list_provisioned_concurrency_configs(FunctionName=fn)["ProvisionedConcurrencyConfigs"]
    qualifiers = sorted(cfg["FunctionArn"].rsplit(":", 1)[-1] for cfg in listed)
    assert qualifiers == [v1], (
        f"only version {v1} may hold a provisioned concurrency config after the refusal; the list "
        f"reports {qualifiers}"
    )

    # ---- beat 5: restore — the inclusive boundary (sum == reserved) is accepted ----
    exact = reserved - half
    lam.put_provisioned_concurrency_config(
        FunctionName=fn, Qualifier=v2, ProvisionedConcurrentExecutions=exact
    )
    ctx.on_cleanup(
        lambda: lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=v2)
    )
    ready_v2 = _wait_pc_ready(lam, fn, v2)
    assert ready_v2["AllocatedProvisionedConcurrentExecutions"] == exact, (
        f"an allocation that brings the total to exactly the reserved concurrency ({half} + {exact} "
        f"= {reserved}) must be honoured in full; version {v2} reports {ready_v2!r}"
    )

    # ---- the pool is one number: the reservation cannot be pulled out from under it ----
    below = reserved - 1
    shrink_err = _client_error(
        lambda: lam.put_function_concurrency(
            FunctionName=fn, ReservedConcurrentExecutions=below
        )
    )
    assert shrink_err.get("Code") == "InvalidParameterValueException", (
        f"lowering reserved concurrency to {below} while {reserved} provisioned executions are "
        f"allocated must be refused with InvalidParameterValueException; got "
        f"{shrink_err.get('Code')!r}: {shrink_err.get('Message')!r}"
    )
    expected_shrink_msg = (
        f" ReservedConcurrentExecutions  {below} should not be lower than function's total "
        f"provisioned concurrency [{reserved}]."
    )
    assert shrink_err.get("Message") == expected_shrink_msg, (
        f"expected the exact reserved-below-provisioned message, got {shrink_err.get('Message')!r}"
    )
    still = lam.get_function_concurrency(FunctionName=fn)["ReservedConcurrentExecutions"]
    assert still == reserved, (
        f"the refused shrink must leave the reservation untouched at {reserved}, "
        f"GetFunctionConcurrency now reports {still}"
    )

    # ---- and raising it is accepted, so the refusal above was the invariant, not a dead API ----
    raised = reserved + 2
    lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=raised)
    now = lam.get_function_concurrency(FunctionName=fn)["ReservedConcurrentExecutions"]
    assert now == raised, (
        f"raising reserved concurrency above the allocated provisioned concurrency must be "
        f"accepted: expected {raised}, GetFunctionConcurrency reports {now}"
    )


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _wait_pc_ready(lam, fn: str, qualifier: str, timeout_s: float = 600.0) -> dict:
    """Wait for a provisioned concurrency allocation to reach Status=READY; FAILED raises."""
    def _probe():
        cfg = lam.get_provisioned_concurrency_config(FunctionName=fn, Qualifier=qualifier)
        if cfg.get("Status") == "FAILED":
            raise AssertionError(
                f"provisioned concurrency on {fn}:{qualifier} entered FAILED: "
                f"{cfg.get('StatusReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("Status") == "READY",
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"provisioned concurrency on {fn}:{qualifier} reaching Status=READY",
    )


def _create_execution_role(ctx, iam) -> str:
    """Create this check's own Lambda execution role."""
    role_name = ctx.unique_name("sim2real-behav-pcpool-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the documented role-propagation refusal; raises on deadline."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _delete_function(ctx, lam, name))
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 90s; last error {last}")


def _delete_function(ctx, lam, name: str) -> None:
    lam.delete_function(FunctionName=name)
    ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {cfg.get('StateReasonCode')} {cfg.get('StateReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{name} reaching State=Active",
    )


def _wait_last_update_successful(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} update failed: {cfg.get('LastUpdateStatusReasonCode')} "
                f"{cfg.get('LastUpdateStatusReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("LastUpdateStatus") == "Successful" and cfg.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{name} reaching LastUpdateStatus=Successful",
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry with a deadline. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
