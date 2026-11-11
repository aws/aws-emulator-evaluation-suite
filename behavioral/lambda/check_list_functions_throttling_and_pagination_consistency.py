"""list-functions-throttling-and-pagination-consistency."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "list-functions-throttling-and-pagination-consistency"
GROUP = 'lifecycle'
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


def _create_fn_nowait(ctx, lam, code, name=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    return name


def _call_with_backoff(fn, attempts=6, base_delay=1.5,
                       retryable_codes=("TooManyRequestsException", "ThrottlingException")):
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in retryable_codes and attempt < attempts - 1:
                last_exc = exc
                time.sleep(min(10, base_delay * (2 ** attempt)))
                continue
            raise
    raise last_exc


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaxItems=1 pagination lists each of our functions exactly once and terminates, with each
    page holding at most one function.
    """
    lam = ctx.client("lambda")
    created = []
    for _ in range(3):
        created.append(_create_fn_nowait(ctx, lam, HANDLER_V1, ctx.unique_name("sim2real-behav-fn-page-")))

    seen_counts: dict[str, int] = {}
    marker = None
    for _ in range(500):
        kwargs = {"MaxItems": 1}
        if marker:
            kwargs["Marker"] = marker
        page = _call_with_backoff(lambda kw=kwargs: lam.list_functions(**kw))
        assert len(page.get("Functions", [])) <= 1, page
        for fn_cfg in page.get("Functions", []):
            seen_counts[fn_cfg["FunctionName"]] = seen_counts.get(fn_cfg["FunctionName"], 0) + 1
        marker = page.get("NextMarker")
        if not marker:
            break
    else:
        raise AssertionError("ListFunctions pagination did not terminate within 500 MaxItems=1 pages")

    for name in created:
        assert seen_counts.get(name) == 1, (
            f"expected {name} to appear exactly once across the full ListFunctions pagination sweep, "
            f"got {seen_counts.get(name)}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
