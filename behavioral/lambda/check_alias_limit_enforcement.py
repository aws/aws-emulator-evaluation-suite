"""alias-limit-enforcement."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "alias-limit-enforcement"
GROUP = 'versions_aliases'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
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
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _call_with_retry(fn, retryable_codes=("TooManyRequestsException",), timeout_s=30, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in retryable_codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating 201 aliases on one function succeeds, or stops on throttling or on
    AliasLimitExceededException above 100; ListAliases returns exactly the created count."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, HANDLER_V1)
    v1 = lam.publish_version(FunctionName=fn)["Version"]

    # The per-function alias cap is not published and is well above 100; probing it fully
    # would exceed the time and throttle budget.
    probe_cap = 200
    created = 0
    limit_code = None
    for i in range(probe_cap + 1):
        try:
            lam.create_alias(FunctionName=fn, Name=f"a{i:04d}", FunctionVersion=v1)
            created += 1
        except ClientError as exc:
            limit_code = exc.response.get("Error", {}).get("Code")
            break

    listed: list = []
    marker = None
    while True:
        kwargs = {"FunctionName": fn, "MaxItems": 10000}
        if marker:
            kwargs["Marker"] = marker
        page = _call_with_retry(lambda kwargs=kwargs: lam.list_aliases(**kwargs))
        listed.extend(page.get("Aliases", []))
        marker = page.get("NextMarker")
        if not marker:
            break
    assert len(listed) == created, f"expected {created} aliases listed, got {len(listed)}"

    if limit_code is None:
        # No rejection within 201 creates is the expected AWS outcome.
        assert created == probe_cap + 1, f"expected {probe_cap + 1} aliases created, got {created}"
    elif limit_code == "TooManyRequestsException":
        # Request-side throttling reached before any count-based cap -- also an unreached boundary.
        assert created > 0, "throttled on the very first CreateAlias; nothing was proven"
    else:
        # message varies: AWS does not reach the cap within 201 creates; only the code is checked.
        assert limit_code == "AliasLimitExceededException", (
            f"expected AliasLimitExceededException after {created} aliases, got {limit_code}"
        )
        assert created > 100, (
            f"AliasLimitExceededException fired at only {created} aliases, at or below the "
            f"already-refuted 100 figure this check exists to disprove"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
