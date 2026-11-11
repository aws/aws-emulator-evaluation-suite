"""get-provisioned-concurrency-nonexistent-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-provisioned-concurrency-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetProvisionedConcurrencyConfig on a version without provisioned concurrency raises
    ProvisionedConcurrencyConfigNotFoundException, while a configured sibling version is
    readable."""
    lam = ctx.client("lambda")
    fn = _create_function(ctx)
    configured_version = lam.publish_version(FunctionName=fn["name"])["Version"]

    # PublishVersion is idempotent on unchanged code: calling it again with nothing new to
    # capture returns the SAME version rather than minting a second one. Change the code first
    # so the second publish is guaranteed to snapshot something distinct.
    lam.update_function_code(FunctionName=fn["name"], ZipFile=_minimal_zip_bytes(marker="v2"))
    _wait_update_settled(lam, fn["name"])
    bare_version = lam.publish_version(FunctionName=fn["name"])["Version"]
    assert configured_version != bare_version, (
        f"expected two distinct published versions, got {configured_version!r} twice"
    )

    put = lam.put_provisioned_concurrency_config(
        FunctionName=fn["name"], Qualifier=configured_version, ProvisionedConcurrentExecutions=1
    )
    ctx.on_cleanup(lambda: _delete_pc_ignore(lam, fn["name"], configured_version))
    assert put["RequestedProvisionedConcurrentExecutions"] == 1, (
        f"expected requested concurrency echoed as 1, got {put.get('RequestedProvisionedConcurrentExecutions')!r}"
    )

    # Positive control: the configured version is readable, so NotFound below is version-specific.
    control_cfg = lam.get_provisioned_concurrency_config(
        FunctionName=fn["name"], Qualifier=configured_version
    )
    assert control_cfg["Status"] in ("IN_PROGRESS", "READY"), (
        f"expected control version to report IN_PROGRESS or READY, got {control_cfg.get('Status')!r}"
    )

    try:
        unexpected = lam.get_provisioned_concurrency_config(FunctionName=fn["name"], Qualifier=bare_version)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"expected GetProvisionedConcurrencyConfig on never-configured version {bare_version!r} "
            f"to be rejected, but it succeeded and returned {unexpected!r}"
        )

    assert error_code == "ProvisionedConcurrencyConfigNotFoundException", (
        f"expected ProvisionedConcurrencyConfigNotFoundException for the never-configured version, got {error_code!r}"
    )
    assert error_message == "No Provisioned Concurrency Config found for this function", error_message

    # same list call carries both: the configured version present, the bare one absent.
    configs = lam.list_provisioned_concurrency_configs(FunctionName=fn["name"])[
        "ProvisionedConcurrencyConfigs"
    ]
    qualifiers = {c["FunctionArn"].split(":")[-1] for c in configs}
    assert configured_version in qualifiers, (
        f"expected {configured_version!r} in ListProvisionedConcurrencyConfigs, got {qualifiers!r}"
    )
    assert bare_version not in qualifiers, (
        f"expected {bare_version!r} absent from ListProvisionedConcurrencyConfigs, got {qualifiers!r}"
    )


def _minimal_zip_bytes(marker: str = "v1") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            f"def handler(event, context):\n    return {{'ok': True, 'marker': {marker!r}}}\n",
        )
    return buf.getvalue()


def _wait_update_settled(lam, name):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state, last_update = cfg.get("State"), cfg.get("LastUpdateStatus")
        if state == "Active" and last_update == "Successful":
            return
        if state == "Failed" or last_update == "Failed":
            raise AssertionError(f"function update failed: {cfg.get('StateReason') or cfg.get('LastUpdateStatusReason')}")
        time.sleep(2)
    raise AssertionError("function code update did not settle in time")


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_active(lam, name):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError("function did not become Active in time")


def _create_function(ctx, **overrides):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    role_arn = _create_lambda_role(ctx)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _minimal_zip_bytes()},
        Timeout=10,
    )
    kwargs.update(overrides)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            resp = lam.create_function(**kwargs)
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and "cannot be assumed" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(lam, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _delete_pc_ignore(lam, function_name: str, qualifier: str) -> None:
    try:
        lam.delete_provisioned_concurrency_config(FunctionName=function_name, Qualifier=qualifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on first invocation. Late log delivery can recreate it,
    so it must stay absent across two reads 5 s apart; a group still present after 30 s raises."""
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
