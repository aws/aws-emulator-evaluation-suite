"""durable-execution-kms-disabled-still-serves-metadata."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "durable-execution-kms-disabled-still-serves-metadata"
GROUP = "server-side"
SERVICES = ["iam", "kms", "lambda", "logs", "sts"]

# A durable handler: one checkpointed step, then the execution returns.
_HANDLER_PY = """\
from aws_durable_execution_sdk_python import DurableContext, durable_execution, durable_step


@durable_step
def echo(step_context, event):
    return {"ok": True, "echoed": event}


@durable_execution
def lambda_handler(event, context: DurableContext):
    return context.step(echo(event))
"""
_ROLE_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy",
)
_TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"}
_TAGS = {"sim2real": CHECK}
_ROLE_NOT_READY = ("InvalidParameterValueException",
                   "The role defined for the function cannot be assumed by Lambda.")
_PRINCIPAL_NOT_READY = ("MalformedPolicyDocumentException",
                        "Policy contains a statement with one or more invalid principals.")


def _pair(exc: ClientError) -> tuple[str | None, str | None]:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With a durable execution's KMS key disabled, a metadata-only GetDurableExecution and
    GetDurableExecutionHistory (IncludeExecutionData=False) still succeed with no execution
    data, while the same calls with IncludeExecutionData=True still fail KMSDisabledException."""
    lam = ctx.client("lambda")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    function_name, key_id, key_arn, durable_execution_arn = _setup(ctx, lam, kms, iam, sts)

    # Positive control: metadata-only reads succeed and are internally consistent while the key
    # is still enabled.
    enabled = _poll_until(
        lambda: lam.get_durable_execution(
            DurableExecutionArn=durable_execution_arn, IncludeExecutionData=False
        ),
        lambda e: e["Status"] in _TERMINAL,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert enabled["Status"] == "SUCCEEDED", (
        f"the synchronously invoked execution should end SUCCEEDED, got {enabled['Status']!r}"
    )
    assert enabled["ExecutionDataIncluded"] is False, (
        f"a metadata-only GetDurableExecution must report ExecutionDataIncluded=false, got "
        f"{enabled['ExecutionDataIncluded']!r}"
    )
    assert enabled["DurableConfig"]["KMSKeyArn"] == key_arn, (
        f"DurableConfig.KMSKeyArn should be {key_arn!r}, got {enabled['DurableConfig']!r}"
    )

    kms.disable_key(KeyId=key_id)

    disabled_msg = (
        "Lambda was unable to access your execution data because the KMS key used is disabled. "
        "Check the KMS key configured in the function's durable config. KMS Exception: "
        f"DisabledException KMS Message: {key_arn} is disabled."
    )

    def _true_call_error():
        try:
            lam.get_durable_execution(DurableExecutionArn=durable_execution_arn, IncludeExecutionData=True)
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")

    error = _poll_until(_true_call_error, lambda c: c is not None, timeout_s=300.0, interval_s=10.0)
    assert error == ("KMSDisabledException", disabled_msg), (
        f"expected GetDurableExecution(IncludeExecutionData=True) to fail with "
        f"('KMSDisabledException', {disabled_msg!r}) once its KMS key was disabled, got {error!r}"
    )

    # The main claim: the False path on GetDurableExecution is unaffected by the disabled key.
    meta = lam.get_durable_execution(DurableExecutionArn=durable_execution_arn, IncludeExecutionData=False)
    assert meta["ExecutionDataIncluded"] is False, (
        f"GetDurableExecution with IncludeExecutionData=False against a disabled KMS key must "
        f"report ExecutionDataIncluded=false, got {meta['ExecutionDataIncluded']!r}"
    )
    assert "InputPayload" not in meta, (
        f"GetDurableExecution with IncludeExecutionData=False must omit InputPayload, got keys "
        f"{sorted(meta)!r}"
    )
    assert "Result" not in meta, (
        f"GetDurableExecution with IncludeExecutionData=False must omit Result, got keys "
        f"{sorted(meta)!r}"
    )
    assert meta["DurableExecutionArn"] == durable_execution_arn, (
        f"GetDurableExecution reported DurableExecutionArn {meta['DurableExecutionArn']!r}, "
        f"expected {durable_execution_arn!r}"
    )
    assert meta["DurableConfig"]["KMSKeyArn"] == key_arn, (
        f"DurableConfig.KMSKeyArn should still read {key_arn!r} with the key disabled, got "
        f"{meta['DurableConfig']!r}"
    )
    assert meta["Status"] == "SUCCEEDED", (
        f"the synchronously invoked execution should read SUCCEEDED with data excluded, got "
        f"{meta['Status']!r}"
    )
    assert meta["StartTimestamp"] == enabled["StartTimestamp"], (
        f"StartTimestamp with the key disabled is {meta['StartTimestamp']!r}, expected the "
        f"{enabled['StartTimestamp']!r} read while the key was enabled"
    )

    # The False path on GetDurableExecutionHistory is unaffected by the disabled key, too.
    hist = lam.get_durable_execution_history(
        DurableExecutionArn=durable_execution_arn, IncludeExecutionData=False
    )
    types = [ev["EventType"] for ev in hist["Events"]]
    assert types[:1] == ["ExecutionStarted"] and types[-1:] == ["ExecutionSucceeded"], (
        f"GetDurableExecutionHistory with IncludeExecutionData=False should run from "
        f"ExecutionStarted to ExecutionSucceeded, got {types!r}"
    )
    for ev in hist["Events"]:
        assert "InputPayload" not in ev, f"history event carried InputPayload with data excluded: {ev!r}"
        assert "Result" not in ev, f"history event carried Result with data excluded: {ev!r}"

    # The True path on GetDurableExecutionHistory still fails the same way.
    hist_error = _error(
        lambda: lam.get_durable_execution_history(
            DurableExecutionArn=durable_execution_arn, IncludeExecutionData=True
        )
    )
    assert hist_error == ("KMSDisabledException", disabled_msg), (
        f"expected GetDurableExecutionHistory(IncludeExecutionData=True) to fail with "
        f"('KMSDisabledException', {disabled_msg!r}) against a disabled KMS key, got {hist_error!r}"
    )


def _error(fn) -> tuple[str, str]:
    """(code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _setup(ctx, lam, kms, iam, sts) -> tuple[str, str, str, str]:
    account_id = sts.get_caller_identity()["Account"]

    role_arn = _create_basic_execution_role(ctx, iam)

    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableIAMUserPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowLambdaServiceForDurableExecution",
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
                "Resource": "*",
            },
            {
                "Sid": "AllowExecutionRole",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    }
    key = _create_key_with_retry(
        kms, ctx.unique_name("sim2real-behav-durkey-"), key_policy
    )
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    function_name = ctx.unique_name("sim2real-behav-durfn-")
    code_zip = _make_zip({"index.py": _HANDLER_PY})
    _create_function_with_retry(
        ctx,
        lam,
        FunctionName=function_name,
        Runtime="python3.13",
        Role=role_arn,
        Handler="index.lambda_handler",
        Code={"ZipFile": code_zip},
        Timeout=60,
        MemorySize=128,
        DurableConfig={"ExecutionTimeout": 900, "KMSKeyArn": key_arn},
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, function_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _wait_for_active(lam, function_name)

    # Durable functions reject invocation against an unqualified ARN/$LATEST; a published
    # version must be used as the invoke qualifier.
    qualifier = lam.publish_version(FunctionName=function_name)["Version"]

    durable_name = ctx.unique_name("durex-")
    resp = lam.invoke(
        FunctionName=function_name,
        Qualifier=qualifier,
        InvocationType="RequestResponse",
        Payload=json.dumps({"hello": "world"}).encode(),
        DurableExecutionName=durable_name,
    )
    durable_execution_arn = resp.get("DurableExecutionArn")
    if not durable_execution_arn:
        raise AssertionError("unreachable: Invoke response did not include a DurableExecutionArn")
    return function_name, key_id, key_arn, durable_execution_arn


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _create_key_with_retry(kms, description: str, key_policy: dict, timeout_s: float = 40.0) -> dict:
    # A key policy naming a just-created IAM role as Principal can be rejected with
    # MalformedPolicyDocumentException until IAM propagation catches up; KMS validates
    # referenced principals exist at policy-write time, so this is a real eventual-consistency
    # race, not a malformed policy.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return kms.create_key(
                Description=description,
                Policy=json.dumps(key_policy),
                Tags=[{"TagKey": k, "TagValue": v} for k, v in _TAGS.items()],
            )["KeyMetadata"]
        except ClientError as exc:
            if _pair(exc) == _PRINCIPAL_NOT_READY:
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _create_basic_execution_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-durablerole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in _ROLE_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(
            lambda pa=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=pa)
        )
    return role["Role"]["Arn"]


def _create_function_with_retry(ctx, lam, *, timeout_s: float = 90.0, **kwargs):
    """CreateFunction, retrying only the exact refusal of a role IAM has not yet propagated."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if _pair(exc) != _ROLE_NOT_READY or time.monotonic() >= deadline:
                raise
        time.sleep(3)


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


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise AssertionError(f"condition not met within {timeout_s}s; last observed {result!r}")


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on first invocation. Late log delivery can recreate it,
    so it must stay absent across two reads 5 s apart; a group still present after 30 s raises."""
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
