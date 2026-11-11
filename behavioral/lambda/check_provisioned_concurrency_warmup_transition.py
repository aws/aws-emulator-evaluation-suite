"""provisioned-concurrency-warmup-transition."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "provisioned-concurrency-warmup-transition"
GROUP = "concurrency"
SERVICES = ["lambda"]


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
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


def _deploy_function(
    ctx,
    lam,
    code,
    *,
    name=None,
    handler="index.handler",
    runtime="python3.12",
    memory=128,
    timeout=30,
    environment=None,
    layers=None,
    ephemeral_storage=None,
    role=None,
):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or _role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
        "Tags": {"sim2real:managed": "true"},
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            # IAM propagation of the role this check just created.
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _client_error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _delete_pc_config(lam, fn, qualifier):
    try:
        lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=qualifier)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=300, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Provisioned concurrency status transitions from IN_PROGRESS to READY after warm-up."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return e", memory=128)
    v1 = lam.publish_version(FunctionName=fn)["Version"]

    put = lam.put_provisioned_concurrency_config(
        FunctionName=fn, Qualifier=v1, ProvisionedConcurrentExecutions=1
    )
    ctx.on_cleanup(lambda: _delete_pc_config(lam, fn, v1))
    assert put["Status"] == "IN_PROGRESS", put
    assert put["RequestedProvisionedConcurrentExecutions"] == 1, put

    ready = _poll_until(
        lambda: lam.get_provisioned_concurrency_config(FunctionName=fn, Qualifier=v1),
        lambda r: r.get("Status") in ("READY", "FAILED"),
        timeout_s=300,
        interval_s=5.0,
        description=f"provisioned concurrency for {fn}:{v1} to leave IN_PROGRESS",
    )
    assert ready["Status"] == "READY", ready
    assert ready["AllocatedProvisionedConcurrentExecutions"] == 1, ready
    assert ready["RequestedProvisionedConcurrentExecutions"] == 1, ready

    lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=v1)
    gone_code, gone_msg = _client_error(
        lambda: lam.get_provisioned_concurrency_config(FunctionName=fn, Qualifier=v1)
    )
    assert gone_code == "ProvisionedConcurrencyConfigNotFoundException", (
        f"expected ProvisionedConcurrencyConfigNotFoundException after delete, got {gone_code}"
    )
    assert gone_msg == "No Provisioned Concurrency Config found for this function", (
        f"unexpected not-found message: {gone_msg!r}"
    )

    # A second delete of the already-removed config is a no-op (unlike Get, which is not-found).
    lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=v1)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
