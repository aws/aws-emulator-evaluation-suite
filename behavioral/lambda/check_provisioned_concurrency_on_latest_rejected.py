"""provisioned-concurrency-on-latest-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioned-concurrency-on-latest-rejected"
GROUP = "concurrency"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutProvisionedConcurrencyConfig on $LATEST is refused while the identical request on a
    published version succeeds, so the refusal is about $LATEST, not a broken call."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-lambda-pc-latest-")
    _create_function(ctx, lam, name=name)
    _wait_active(lam, name)
    version = lam.publish_version(FunctionName=name)["Version"]

    # ---- positive control: the identical request on a real published version is accepted ----
    control_put = lam.put_provisioned_concurrency_config(
        FunctionName=name, Qualifier=version, ProvisionedConcurrentExecutions=1
    )
    # Registered immediately (a provisioned config bills from the moment it is READY), so the
    # delete below must not depend on reaching READY first.
    ctx.on_cleanup(
        lambda: _delete_pc_ignore(lam, name, version)
    )
    assert control_put["RequestedProvisionedConcurrentExecutions"] == 1, (
        f"the control's Put on version {version} did not record the requested concurrency: {control_put!r}"
    )
    control_read = lam.get_provisioned_concurrency_config(FunctionName=name, Qualifier=version)
    assert control_read["RequestedProvisionedConcurrentExecutions"] == 1, (
        f"the control's config on version {version} did not persist: {control_read!r}"
    )
    assert control_read["Status"] in ("IN_PROGRESS", "READY"), (
        f"the control's provisioned config on version {version} reports {control_read['Status']!r}; "
        f"it is deliberately not waited to READY, but it must be allocating or allocated"
    )

    # ---- break exactly one thing: ask for the same config on $LATEST instead ----
    code, code_msg = _error(
        lambda: lam.put_provisioned_concurrency_config(
            FunctionName=name, Qualifier="$LATEST", ProvisionedConcurrentExecutions=1
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for $LATEST provisioned concurrency, got {code}"
    )
    assert code_msg == "Provisioned Concurrency Configs cannot be applied to unpublished function versions.", (
        f"expected the exact 'InvalidParameterValueException' message, got {code_msg!r}"
    )

    # ---- the effect is absent: $LATEST is not a queryable qualifier either, by an
    # independent read path, and no config exists under it ----
    absent, absent_msg = _error(
        lambda: lam.get_provisioned_concurrency_config(FunctionName=name, Qualifier="$LATEST")
    )
    assert absent == "InvalidParameterValueException", (
        f"reading back the refused $LATEST config returned {absent!r} instead of "
        f"InvalidParameterValueException — real AWS rejects $LATEST identically on read and on "
        f"write, it is never a valid qualifier for provisioned concurrency"
    )
    assert absent_msg == "The function resource provided must be an alias or a published version.", (
        f"expected the exact 'InvalidParameterValueException' message, got {absent_msg!r}"
    )
    listed = []
    paginator = lam.get_paginator("list_provisioned_concurrency_configs")
    for page in paginator.paginate(FunctionName=name):
        listed.extend(page.get("ProvisionedConcurrencyConfigs", []))
    qualifiers = {c["FunctionArn"].rsplit(":", 1)[-1] for c in listed}
    assert qualifiers == {version}, (
        f"expected only the control's version {version!r} to have a provisioned-concurrency "
        f"config, got qualifiers {qualifiers!r} — the refused $LATEST Put left a config behind"
    )


# ===== helpers =====

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
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


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


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=1.5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _delete_pc_ignore(lam, name: str, qualifier: str) -> None:
    try:
        lam.delete_provisioned_concurrency_config(FunctionName=name, Qualifier=qualifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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

    Deliberately does not raise on Failed: a Failed function surfaces as a service
    error on the next call.
    """
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"function {name} to leave Pending",
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
    role propagation (the classic "cannot be assumed by Lambda" race)."""
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
    )
    if env is not None:
        params["Environment"] = {"Variables": env}
    params.setdefault("Tags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})
    params.update(kwargs)

    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    left = ctx.time_left()
    deadline = time.monotonic() + (90.0 if left is None else min(90.0, left))
    while True:
        try:
            return lam.create_function(**params)
        except ClientError as exc:
            msg = str(exc)
            role_not_ready = "cannot be assumed" in msg or (
                "InvalidParameterValueException" in msg and "role" in msg.lower()
            )
            if not role_not_ready or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
