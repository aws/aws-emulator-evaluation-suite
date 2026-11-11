"""list-versions-by-function-ordering."""

from __future__ import annotations

import io
import json
import random
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-versions-by-function-ordering"
GROUP = "versions_aliases"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVersionsByFunction returns $LATEST first, then the published versions in ascending
    numeric order (the observed order; the API documents none)."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-lambda-list-ver-")
    _create_function(ctx, lam, name=name)
    _wait_active(lam, name)

    published = []
    for _ in range(3):
        v = lam.publish_version(FunctionName=name)
        published.append(v["Version"])
        lam.update_function_code(FunctionName=name, ZipFile=_make_zip(_bump_src()))
        _wait_update_done(lam, name)

    resp = lam.list_versions_by_function(FunctionName=name)
    versions = [v["Version"] for v in resp["Versions"]]
    assert sorted(versions) == sorted(["$LATEST", *published]), (
        f"expected exactly $LATEST plus the published versions {published}, got {versions}"
    )
    assert len(set(published)) == 3, f"each publish should mint a distinct version, got {published}"
    # The API documents no list order; this is the order AWS is observed to return.
    assert versions[0] == "$LATEST", f"expected $LATEST first, got {versions}"
    numeric = [int(v) for v in versions[1:]]
    assert numeric == sorted(numeric), f"expected ascending version order, got {numeric}"


def _bump_src() -> str:
    """A distinct code payload per publish, so each version really differs."""
    return f"""
def handler(event, context):
    return {{"echo": event, "salt": {random.randint(0, 10**6)}}}
"""


_DEFAULT_HANDLER_SRC = """
import json

def handler(event, context):
    if isinstance(event, dict) and event.get("fail"):
        raise Exception("intentional-failure: " + str(event.get("fail")))
    return {"echo": event}
"""


def _make_zip(src: str = _DEFAULT_HANDLER_SRC, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
    return buf.getvalue()


_ROLES: dict = {}


def _role_arn(ctx) -> str:
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
    policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    _ROLES[id(ctx)] = arn
    return arn


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=1.5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _cleanup_fn(ctx, lam, name: str) -> None:
    """Delete the function and the log group Lambda implicitly creates for it."""
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


def _wait_active(lam, name: str, timeout_s: float = 90, interval_s: float = 1.5):
    """Poll until State settles at Active or Failed.

    Deliberately does NOT raise on Failed: a Failed function surfaces as a real
    service error on the next call.
    """
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"function {name} to leave Pending",
    )


def _wait_update_done(lam, name: str, timeout_s: float = 90, interval_s: float = 1.5):
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("LastUpdateStatus") in ("Successful", "Failed", None),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"function {name} update to settle",
    )


def _create_function(
    ctx,
    lam,
    name=None,
    src: str = _DEFAULT_HANDLER_SRC,
    handler: str = "index.handler",
    runtime: str = "python3.12",
    timeout: int = 15,
    memory: int = 128,
    role_arn: str | None = None,
    env: dict | None = None,
    **kwargs,
):
    """CreateFunction with teardown registered up front and bounded retry on IAM
    role propagation (the classic "cannot be assumed by Lambda" race).
    """
    name = name or ctx.unique_name("sim2real-behav-lambda-fn-")
    params = dict(
        FunctionName=name,
        Runtime=runtime,
        Role=role_arn or _role_arn(ctx),
        Handler=handler,
        Code={"ZipFile": _make_zip(src)},
        Timeout=timeout,
        MemorySize=memory,
        Publish=False,
        Tags={"sim2real": "list-versions-by-function-ordering"},
    )
    if env is not None:
        params["Environment"] = {"Variables": env}
    params.update(kwargs)

    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    last_exc = None
    for _ in range(8):
        try:
            return lam.create_function(**params)
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or (
                "InvalidParameterValueException" in msg and "role" in msg.lower()
            ):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
