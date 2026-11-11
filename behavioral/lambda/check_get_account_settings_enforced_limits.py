"""get-account-settings-enforced-limits."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-settings-enforced-limits"
GROUP = "server-side"
SERVICES = ["lambda"]

#: Fresh attempts before a concurrent change elsewhere in the account counts as a failure.
_ATTEMPTS = 3


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountSettings' reported AccountLimit/AccountUsage numbers are not just cosmetic:
    the account's unreserved-concurrency pool they report is enforced server-side by
    PutFunctionConcurrency, and AccountUsage.FunctionCount tracks real CreateFunction calls."""
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    role_arn = _create_basic_execution_role(ctx, iam)
    code_zip = _make_zip({"lambda_function.py": "def handler(event, context):\n    return event\n"})

    # AccountUsage.FunctionCount is account-wide, so a function another run deletes meanwhile
    # hides ours: each attempt creates a fresh function, and only a window in which the count rose
    # by at least our own one is graded.
    for _ in range(_ATTEMPTS):
        usage0 = lam.get_account_settings()["AccountUsage"]["FunctionCount"]
        function_name = ctx.unique_name("sim2real-behav-acctfn-")
        _create_function_with_retry(
            ctx,
            lam,
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": code_zip},
            Timeout=10,
            MemorySize=128,
            Tags={"sim2real:managed": "true"},
        )
        ctx.on_cleanup(lambda name=function_name: lam.delete_function(FunctionName=name))
        _wait_for_active(lam, function_name)

        # AccountUsage.FunctionCount must reflect the function we just created.
        usage1 = _poll_until(
            lambda: lam.get_account_settings()["AccountUsage"]["FunctionCount"],
            lambda count, usage0=usage0: count >= usage0 + 1,
            timeout_s=30.0,
            interval_s=2.0,
        )
        if usage1 >= usage0 + 1:
            break
    assert usage1 >= usage0 + 1, (
        f"AccountUsage.FunctionCount did not increase after CreateFunction ({usage0} -> {usage1}) "
        f"in the last of {_ATTEMPTS} attempts"
    )

    # Baseline the currently-reported unreserved pool right before probing it.
    limit = lam.get_account_settings()["AccountLimit"]
    unreserved = limit["UnreservedConcurrentExecutions"]

    # Overly-permissive boundary: requesting more reserved concurrency than the account's
    # reported unreserved pool must be rejected server-side, not silently accepted.
    over_request = unreserved + 1000
    code, message = _error(
        lambda: lam.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=over_request
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException reserving {over_request} (> unreserved pool "
        f"{unreserved}), got {code!r}"
    )
    expected_message = (
        "Specified ReservedConcurrentExecutions for function decreases account's "
        "UnreservedConcurrentExecution below its minimum value of "
        f"[{limit['ConcurrentExecutions'] // 10}]."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r} reserving {over_request}, got {message!r}"
    )

    # The rejected over-limit reservation must not have taken effect: an independent read
    # through GetFunctionConcurrency must still show no reservation in place.
    after_reject = lam.get_function_concurrency(FunctionName=function_name)
    assert "ReservedConcurrentExecutions" not in after_reject, (
        f"rejected over-limit PutFunctionConcurrency must not leave a reservation in place, "
        f"got {after_reject!r}"
    )

    # A small, in-bounds reservation must succeed and be reflected back in the account's
    # reported unreserved pool (it should shrink by exactly the amount reserved). The pool is
    # account-wide, so a reservation another run makes or releases meanwhile moves it too: each
    # attempt reserves afresh, and only a window in which the pool moved by exactly our own one
    # is graded.
    ctx.on_cleanup(lambda: _delete_function_concurrency(lam, function_name))
    for _ in range(_ATTEMPTS):
        unreserved = lam.get_account_settings()["AccountLimit"]["UnreservedConcurrentExecutions"]
        lam.put_function_concurrency(FunctionName=function_name, ReservedConcurrentExecutions=1)
        unreserved_after = _poll_until(
            lambda: lam.get_account_settings()["AccountLimit"]["UnreservedConcurrentExecutions"],
            lambda v, unreserved=unreserved: v == unreserved - 1,
            timeout_s=30.0,
            interval_s=2.0,
        )
        if unreserved_after == unreserved - 1:
            break
        _delete_function_concurrency(lam, function_name)
    assert unreserved_after == unreserved - 1, (
        f"reserving 1 concurrent execution did not shrink the reported unreserved pool by 1 "
        f"({unreserved} -> {unreserved_after}) in the last of {_ATTEMPTS} attempts"
    )


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _create_basic_execution_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-acctrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_function_with_retry(ctx, lam, **kwargs):
    last_exc = None
    for _ in range(10):
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidParameterValueException", "ResourceConflictException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _wait_for_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        if cfg.get("State") == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function {name} did not become Active within {timeout_s}s")


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    """probe() once predicate holds, else the last value read at the deadline."""
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _delete_function_concurrency(lam, name: str) -> None:
    """Remove the function's reservation; a function already gone has none."""
    try:
        lam.delete_function_concurrency(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
