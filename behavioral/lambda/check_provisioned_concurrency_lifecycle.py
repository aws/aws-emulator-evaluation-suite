"""provisioned-concurrency-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "provisioned-concurrency-lifecycle"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Provisioned concurrency config transitions through allocating states and is removed after delete."""
    lam = ctx.client("lambda")
    fn = _create_basic_function(ctx)
    version = lam.publish_version(FunctionName=fn["name"])["Version"]

    put = lam.put_provisioned_concurrency_config(
        FunctionName=fn["name"], Qualifier=version, ProvisionedConcurrentExecutions=1
    )
    ctx.on_cleanup(lambda: _delete_pc_ignore(lam, fn["name"], version))
    assert put["RequestedProvisionedConcurrentExecutions"] == 1, f"expected requested=1, got {put['RequestedProvisionedConcurrentExecutions']}"
    assert put["Status"] in ("IN_PROGRESS", "READY"), f"unexpected initial status: {put['Status']}"

    settled = _poll_until(
        lambda: lam.get_provisioned_concurrency_config(FunctionName=fn["name"], Qualifier=version),
        lambda cfg: cfg["Status"] in ("READY", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert settled["Status"] == "READY", f"provisioned concurrency ended in {settled['Status']}: {settled.get('StatusReason')}"
    assert settled["AllocatedProvisionedConcurrentExecutions"] == 1, f"expected allocated=1, got {settled['AllocatedProvisionedConcurrentExecutions']}"

    configs = lam.list_provisioned_concurrency_configs(FunctionName=fn["name"])["ProvisionedConcurrencyConfigs"]
    qualifiers = {c["FunctionArn"].split(":")[-1] for c in configs}
    assert version in qualifiers, "provisioned concurrency config missing from ListProvisionedConcurrencyConfigs"

    lam.delete_provisioned_concurrency_config(FunctionName=fn["name"], Qualifier=version)

    code, msg = _error(
        lambda: lam.get_provisioned_concurrency_config(FunctionName=fn["name"], Qualifier=version)
    )
    assert code == "ProvisionedConcurrencyConfigNotFoundException", f"unexpected code: {code}"
    assert msg == "No Provisioned Concurrency Config found for this function", (
        f"expected the exact config-not-found message, got {msg!r}"
    )

    configs_after = lam.list_provisioned_concurrency_configs(FunctionName=fn["name"])["ProvisionedConcurrencyConfigs"]
    assert configs_after == [], "provisioned concurrency config still listed after delete"

    # DeleteProvisionedConcurrencyConfig on an already-deleted config is idempotent on real AWS:
    # the second delete succeeds, so any ClientError here fails the check.
    lam.delete_provisioned_concurrency_config(FunctionName=fn["name"], Qualifier=version)


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_basic_function(ctx) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                Timeout=10,
                MemorySize=128,
                Publish=False,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
            )
            break
        except Exception as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValueException" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError("create_function never succeeded (role propagation timeout)")
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _wait_function_active(ctx, name: str) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return cfg
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function did not become Active in time (last={cfg!r})")


def _delete_pc_ignore(lam, function_name: str, qualifier: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_provisioned_concurrency_config(FunctionName=function_name, Qualifier=qualifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across two reads 5 s apart. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not present():
            time.sleep(5.0)
            if not present():
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
