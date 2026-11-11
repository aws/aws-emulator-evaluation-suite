"""durable-execution-kms-enforcement-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "durable-execution-kms-enforcement-rejected"
GROUP = "server-side"
SERVICES = ["lambda"]

#: The execution must still be running when Get/Stop are graded, which can be well after the key
#: is disabled (the data-key cache window below), so the handler holds the execution open for
#: Lambda's maximum function timeout (900s) less a margin.
_HOLD_S = 840
_HANDLER_SRC = (
    "def handler(event, context):\n    import time\n"
    f"    time.sleep({_HOLD_S})\n    return {{'ok': True}}\n"
)
_KMS_CODES = ("KMSDisabledException", "KMSAccessDeniedException")


def _kms_disabled_msg(key_arn: str) -> str:
    return (
        "Lambda was unable to access your execution data because the KMS key used is disabled. "
        "Check the KMS key configured in the function's durable config. KMS Exception: "
        f"DisabledException KMS Message: {key_arn} is disabled."
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With the DurableConfig KMS key disabled, Get/StopDurableExecution are rejected with a KMS
    error and the execution is not STOPPED; a twin execution with an enabled key still works.
    """
    lam = ctx.client("lambda")
    for op in ("get_durable_execution", "stop_durable_execution", "list_durable_executions_by_function"):
        if not hasattr(lam, op):
            raise AssertionError(f"unreachable: {op} not present in this botocore version")

    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_arn = _create_basic_lambda_role(ctx)

    key_id, key_arn = _create_durable_kms_key(ctx, kms, account_id, "target")
    _twin_key_id, twin_key_arn = _create_durable_kms_key(ctx, kms, account_id, "twin")

    fn_name = _create_durable_function(ctx, lam, role_arn, key_arn, "sim2real-durable-")
    twin_fn_name = _create_durable_function(ctx, lam, role_arn, twin_key_arn, "sim2real-durable-twin-")

    execution_arn = _start_durable_execution(ctx, lam, fn_name, "durexec-")
    twin_execution_arn = _start_durable_execution(ctx, lam, twin_fn_name, "durexec-twin-")

    # ---- positive control: the target execution is readable before anything is broken ----
    try:
        lam.get_durable_execution(DurableExecutionArn=execution_arn)
    except ClientError as e:
        raise AssertionError(f"unreachable: GetDurableExecution failed before any KMS interference: {e}")

    # ---- break exactly one thing: disable the target's key, leaving the twin's key enabled ----
    kms.disable_key(KeyId=key_id)
    disabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "Disabled",
        timeout_s=20,
        interval_s=1,
    )
    assert disabled == "Disabled", f"KMS key never reached Disabled state (last={disabled})"

    # Lambda caches the durable-execution data key for up to ~15 minutes, so a read right after
    # disabling the key can still succeed; poll past that window rather than assert at once.
    get_deadline = time.monotonic() + 17 * 60
    while True:
        try:
            lam.get_durable_execution(DurableExecutionArn=execution_arn, IncludeExecutionData=True)
        except ClientError as exc:
            get_code = exc.response["Error"]["Code"]
            get_msg = exc.response["Error"].get("Message", "")
            break
        if time.monotonic() >= get_deadline:
            raise AssertionError(
                "GetDurableExecution kept succeeding for 17 minutes after the KMS key was disabled "
                "— past Lambda's documented ~15-minute durable-execution data-key cache window"
            )
        time.sleep(2)
    assert get_code in _KMS_CODES, (
        f"expected GetDurableExecution to be rejected with a KMS error once the key was "
        f"disabled, got {get_code!r} ({get_msg!r})"
    )
    assert get_msg == _kms_disabled_msg(key_arn), f"unexpected GetDurableExecution message: {get_msg!r}"

    stop_code, stop_msg = _client_error(
        lambda: lam.stop_durable_execution(DurableExecutionArn=execution_arn)
    )
    assert stop_code in _KMS_CODES, (
        f"expected StopDurableExecution to be rejected with a KMS error once the key was "
        f"disabled, got {stop_code!r} ({stop_msg!r})"
    )
    assert stop_msg == _kms_disabled_msg(key_arn), f"unexpected StopDurableExecution message: {stop_msg!r}"

    # ---- the effect is absent: the rejected Stop did not actually stop the execution ----
    # With the key disabled the execution can end up FAILED on its own (it cannot checkpoint), so
    # only STOPPED, which only a successful Stop produces, is asserted absent.
    status_after_rejected_stop = _find_execution_status(lam, fn_name, execution_arn)
    assert status_after_rejected_stop != "STOPPED", (
        "StopDurableExecution was rejected with a KMS error but the execution's status advanced "
        "to STOPPED anyway — the rejection was not enforced"
    )

    # ---- twin control: the same calls succeed while its key stays enabled ----
    try:
        lam.get_durable_execution(DurableExecutionArn=twin_execution_arn, IncludeExecutionData=True)
    except ClientError as e:
        raise AssertionError(
            f"twin control failed: GetDurableExecution against an execution whose KMS key was "
            f"never disabled should succeed, got {e}"
        )
    try:
        lam.stop_durable_execution(DurableExecutionArn=twin_execution_arn)
    except ClientError as e:
        raise AssertionError(
            f"twin control failed: StopDurableExecution against an execution whose KMS key was "
            f"never disabled should succeed, got {e}"
        )


def _client_error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _zip_from_files(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _create_basic_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
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


def _create_durable_kms_key(ctx, kms, account_id: str, role_in_policy_sid: str) -> tuple[str, str]:
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
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
        ],
    }
    key = kms.create_key(
        Description=f"sim2real durable-execution KMS enforcement test key ({role_in_policy_sid})",
        Policy=json.dumps(key_policy),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id, key["Arn"]


def _create_durable_function(ctx, lam, role_arn: str, key_arn: str, name_prefix: str) -> str:
    fn_name = ctx.unique_name(name_prefix)
    zip_bytes = _zip_from_files({"index.py": _HANDLER_SRC})
    try:
        _create_function_with_retry(
            ctx,
            lam,
            fn_name,
            role_arn,
            zip_bytes,
            handler="index.handler",
            runtime="python3.12",
            timeout=_HOLD_S + 60,
            extra={
                "DurableConfig": {
                    "ExecutionTimeout": _HOLD_S + 300,
                    "RetentionPeriodInDays": 1,
                    "KMSKeyArn": key_arn,
                },
                "Tags": {"sim2real:managed": "true"},
            },
        )
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"unreachable: could not create a durable function ({e})")
    _wait_function_active(ctx, lam, fn_name)
    return fn_name


def _start_durable_execution(ctx, lam, fn_name: str, name_prefix: str) -> str:
    # Durable functions reject invocation against an unqualified ARN/$LATEST; a published
    # version (or alias pointing at one) must be used as the invoke qualifier.
    publish_resp = lam.publish_version(FunctionName=fn_name)
    qualifier = publish_resp["Version"]

    exec_name = ctx.unique_name(name_prefix)
    lam.invoke(
        FunctionName=fn_name,
        Qualifier=qualifier,
        InvocationType="Event",
        DurableExecutionName=exec_name,
        Payload=b"{}",
    )

    execution_arn = _poll_until(
        lambda: _find_execution_arn(lam, fn_name, exec_name),
        lambda arn: arn is not None,
        timeout_s=30,
        interval_s=1.5,
    )
    if not execution_arn:
        raise AssertionError(
            "durable execution never registered under ListDurableExecutionsByFunction; "
            "cannot validate KMS enforcement without a real execution ARN"
        )
    return execution_arn


def _find_execution_status(lam, fn_name: str, execution_arn: str) -> str:
    execs = lam.list_durable_executions_by_function(FunctionName=fn_name)["DurableExecutions"]
    for execution in execs:
        if execution["DurableExecutionArn"] == execution_arn:
            return execution["Status"]
    raise AssertionError(f"{execution_arn} no longer appears under ListDurableExecutionsByFunction")


def _create_function_with_retry(
    ctx, lam, name, role_arn, zip_bytes, handler, runtime, timeout=30, extra=None
):
    kwargs = dict(
        FunctionName=name,
        Runtime=runtime,
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=False,
    )
    if extra:
        kwargs.update(extra)
    last_err = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            return resp
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "role" in msg.lower():
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


def _wait_function_active(ctx, lam, name, timeout_s=90):
    deadline = time.monotonic() + timeout_s
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            return cfg
        if state == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function did not become Active in time (last state={cfg})")


def _find_execution_arn(lam, fn_name, exec_name):
    try:
        resp = lam.list_durable_executions_by_function(FunctionName=fn_name)
    except Exception:
        return None
    for execution in resp.get("DurableExecutions", []):
        if execution.get("DurableExecutionName") == exec_name:
            return execution.get("DurableExecutionArn") or execution.get("Arn")
    return None


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
