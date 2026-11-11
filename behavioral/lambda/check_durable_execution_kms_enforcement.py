"""durable-execution-kms-enforcement."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "durable-execution-kms-enforcement"
GROUP = "server-side"
SERVICES = ["lambda"]

_HANDLER_JS = "exports.handler = async (event) => { return { ok: true, echoed: event }; };\n"
_TERMINAL_STATUSES = {"SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"}


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once the KMS key in a durable function's DurableConfig is disabled, Get/Stop calls that
    decrypt execution data are rejected with KMSDisabledException; re-enabling the key restores
    access."""
    lam = ctx.client("lambda")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    try:
        function_name, key_id, durable_execution_arn = _setup(ctx, lam, kms, iam, sts)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 - environment/prerequisite failure
        raise AssertionError(f"unreachable: could not provision durable execution + KMS enforcement setup: {exc}") from exc

    # Sanity: while the key is enabled, reading the execution's data works (it may still be
    # running). IncludeExecutionData=True is what forces the server to decrypt the KMS-protected
    # payload; a plain metadata-only GetDurableExecution never touches the key and would pass
    # against any target regardless of key state.
    try:
        lam.get_durable_execution(DurableExecutionArn=durable_execution_arn, IncludeExecutionData=True)
    except ClientError as exc:
        raise AssertionError(f"unreachable: GetDurableExecution failed before any KMS interference: {exc}") from exc

    kms.disable_key(KeyId=key_id)

    def _get_error():
        try:
            lam.get_durable_execution(DurableExecutionArn=durable_execution_arn, IncludeExecutionData=True)
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")

    code, msg = _poll_until(_get_error, lambda c: c is not None, timeout_s=300.0, interval_s=10.0)
    assert code == "KMSDisabledException", (
        f"expected KMSDisabledException from GetDurableExecution once its KMS key was "
        f"disabled, got {code!r}"
    )
    key_arn = f"arn:aws:kms:{ctx.region}:{ctx.account}:key/{key_id}"
    disabled_msg = (
        "Lambda was unable to access your execution data because the KMS key used is disabled. "
        "Check the KMS key configured in the function's durable config. KMS Exception: "
        f"DisabledException KMS Message: {key_arn} is disabled."
    )
    assert msg == disabled_msg, f"GetDurableExecution KMS refusal message: {msg!r}"

    # StopDurableExecution must also refuse to operate on execution data it can no longer
    # decrypt, with the same KMS rejection.
    stop_code, stop_msg = _client_error(
        lambda: lam.stop_durable_execution(DurableExecutionArn=durable_execution_arn)
    )
    assert (stop_code, stop_msg) == ("KMSDisabledException", disabled_msg), (
        f"expected StopDurableExecution to reject a KMS-disabled durable execution, got "
        f"{(stop_code, stop_msg)!r}"
    )

    # The block is a KMS key state, not a permanent condition: once the key is re-enabled, the
    # identical GetDurableExecution call must succeed again rather than staying wedged.
    kms.enable_key(KeyId=key_id)
    restore_code = _poll_until(_get_error, lambda c: c is None, timeout_s=45.0, interval_s=3.0)
    assert restore_code is None, (
        f"expected GetDurableExecution to succeed again once the KMS key was re-enabled, "
        f"got {restore_code!r}"
    )


def _setup(ctx, lam, kms, iam, sts) -> tuple[str, str, str]:
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
                "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
                "Resource": "*",
            },
            {
                "Sid": "AllowExecutionRoleDecrypt",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "kms:Decrypt",
                "Resource": "*",
            },
        ],
    }
    key = _create_key_with_retry(
        kms, ctx.unique_name("sim2real-behav-durable-key-"), key_policy
    )
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    function_name = ctx.unique_name("sim2real-behav-durablefn-")
    code_zip = _make_zip({"index.js": _HANDLER_JS})
    _create_function_with_retry(
        ctx,
        lam,
        FunctionName=function_name,
        Runtime="nodejs20.x",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": code_zip},
        Timeout=60,
        MemorySize=128,
        DurableConfig={"ExecutionTimeout": 900, "KMSKeyArn": key_arn},
        Tags={"sim2real:managed": "true"},
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
    return function_name, key_id, durable_execution_arn


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
                Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
            )["KeyMetadata"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "MalformedPolicyDocumentException":
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


def _client_error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


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
