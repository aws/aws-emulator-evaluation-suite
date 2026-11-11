"""durable-execution-kms-errors."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "durable-execution-kms-errors"
GROUP = 'errors'
SERVICES = ['lambda']

DURABLE_RUNTIME = "python3.13"
DURABLE_HANDLER_ENTRY = "index.lambda_handler"

# A minimal durable function: a single step, then returns.
DURABLE_HANDLER_SRC = """
from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
    durable_step,
)


@durable_step
def step_one(step_context, n):
    return {"step": "one", "n": n}


@durable_execution
def lambda_handler(event, context: DurableContext):
    n = event.get("n", 0)
    r1 = context.step(step_one(n))
    return {"r1": r1}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _account(ctx):
    return ctx.account


def _error_code(fn):
    """The error code of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _read_refused(lam, arn):
    """True once GetDurableExecution with execution data is refused, False while it succeeds."""
    try:
        lam.get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=True)
    except ClientError:
        return True
    return False


def _durable_role_arn(ctx):
    """Create an IAM role with durable-execution + basic-execution permissions; return its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-durrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]

    def _cleanup_role():
        for pa in ("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                   "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy"):
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pa)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    for pa in ("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
               "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy"):
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=pa)
        except ClientError:
            pass
    return arn


def _create_kms_key(ctx, role_arn):
    """Create a KMS key usable as DurableConfig.KMSKeyArn, granting the account root, the Lambda
    service principal and the durable role. Return (key_id, arn)."""
    kms = ctx.client("kms")
    account = _account(ctx)
    statements = [
        {"Sid": "EnableIAMUserPermissions", "Effect": "Allow",
         "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "kms:*", "Resource": "*"},
        {"Sid": "AllowLambdaServiceForDurableFunctions", "Effect": "Allow",
         "Principal": {"Service": "lambda.amazonaws.com"},
         "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"], "Resource": "*"},
        {"Sid": "AllowDurableRole", "Effect": "Allow", "Principal": {"AWS": role_arn},
         "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"], "Resource": "*"},
    ]
    policy = json.dumps({"Version": "2012-10-17", "Statement": statements})
    deadline = time.monotonic() + 30
    last_exc = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = kms.create_key(
                Description="sim2real-behav lambda test key", Policy=policy,
                Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "MalformedPolicyDocumentException":
                last_exc = exc
                time.sleep(2)
                continue
            raise
    if resp is None:
        raise last_exc
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id, resp["KeyMetadata"]["Arn"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Durable-execution read and checkpoint calls fail with a KMS-family error once the
    DurableConfig.KMSKeyArn key is disabled after a real execution has persisted data under it.
    """
    lam = ctx.client("lambda")
    kms = ctx.client("kms")
    role_arn = _durable_role_arn(ctx)
    try:
        key_id, key_arn = _create_kms_key(ctx, role_arn)
        fn = ctx.unique_name("sim2real-behav-durfn-")
        # A freshly-attached role policy can take a few seconds to propagate through IAM before
        # Lambda can assume it; retry the specific "cannot be assumed" race, bounded, rather than
        # sleeping blind up front.
        deadline = time.monotonic() + 30
        last_exc = None
        created = False
        while time.monotonic() < deadline:
            try:
                ctx.on_cleanup(lambda _n=fn: _delete_lambda_log_group(ctx, _n))
                lam.create_function(
                    FunctionName=fn, Runtime=DURABLE_RUNTIME, Role=role_arn,
                    Handler=DURABLE_HANDLER_ENTRY, Code={"ZipFile": _make_zip(DURABLE_HANDLER_SRC)},
                    Timeout=120, MemorySize=128,
                    DurableConfig={"ExecutionTimeout": 300, "RetentionPeriodInDays": 7, "KMSKeyArn": key_arn},
                )
                created = True
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException" and (
                    "cannot be assumed" in str(exc)
                ):
                    last_exc = exc
                    time.sleep(2)
                    continue
                raise
        if not created:
            raise last_exc
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"durable functions (with a customer KMS key) not usable here: {exc}") from None

    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if lam.get_function_configuration(FunctionName=fn)["State"] == "Active":
            break
        time.sleep(2.0)

    v1 = lam.publish_version(FunctionName=fn)["Version"]
    execution_name = ctx.unique_name("sim2real-behav-durex-")
    resp = lam.invoke(
        FunctionName=fn, Qualifier=v1, InvocationType="Event",
        DurableExecutionName=execution_name, Payload=json.dumps({"n": 1}).encode("utf-8"),
    )
    arn = resp.get("DurableExecutionArn")
    if not arn:
        found = None
        d2 = time.monotonic() + 30
        while time.monotonic() < d2:
            listed = lam.list_durable_executions_by_function(
                FunctionName=fn, Qualifier=v1, DurableExecutionName=execution_name
            ).get("DurableExecutions", [])
            if listed:
                found = listed[0]["DurableExecutionArn"]
                break
            time.sleep(2.0)
        arn = found
    assert arn, "could not resolve a DurableExecutionArn"

    # Let the (single-step) execution settle while the key is still enabled.
    def _probe_settled():
        try:
            return lam.get_durable_execution(DurableExecutionArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return {"Status": None}
            raise

    d3 = time.monotonic() + 60
    while time.monotonic() < d3:
        if _probe_settled().get("Status") not in (None, "PENDING", "RUNNING"):
            break
        time.sleep(2.0)

    kms.disable_key(KeyId=key_id)
    kms_codes = ("KMSDisabledException", "KMSAccessDeniedException")

    # Lambda documents an up-to-~15-minute durable-execution data-key cache, so a read right
    # after disabling hits the warm cache; poll past that window rather than assert the first read.
    get_deadline = time.monotonic() + 17 * 60
    refused = _read_refused(lam, arn)
    while not refused and time.monotonic() < get_deadline:
        time.sleep(2)
        refused = _read_refused(lam, arn)
    if not refused:
        raise AssertionError(
            "GetDurableExecution kept succeeding for 17 minutes after the KMS key was disabled — "
            "past Lambda's documented ~15-minute durable-execution data-key cache window"
        )
    disabled_msg = (
        "Lambda was unable to access your execution data because the KMS key used is disabled. "
        "Check the KMS key configured in the function's durable config. KMS Exception: "
        f"DisabledException KMS Message: {key_arn} is disabled."
    )
    get_code, get_msg = _error(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=True)
    )
    assert get_code in kms_codes, f"GetDurableExecution: expected a KMS-family error, got {get_code}"
    if get_code == "KMSDisabledException":
        assert get_msg == disabled_msg, get_msg

    hist_code, hist_msg = _error(
        lambda: lam.get_durable_execution_history(DurableExecutionArn=arn, IncludeExecutionData=True)
    )
    assert hist_code in kms_codes, f"GetDurableExecutionHistory: expected a KMS-family error, got {hist_code}"
    if hist_code == "KMSDisabledException":
        assert hist_msg == disabled_msg, hist_msg

    # GetDurableExecutionState requires CheckpointToken; botocore does not enforce the token's
    # pattern, so a synthetic value reaches the service.
    state_code = _error_code(
        lambda: lam.get_durable_execution_state(DurableExecutionArn=arn, CheckpointToken="AAAA")
    )
    assert state_code in kms_codes + ("InvalidParameterValueException", "ResourceConflictException"), (
        f"GetDurableExecutionState: expected a KMS-family/validation/conflict error, got {state_code}"
    )

    checkpoint_code = _error_code(
        lambda: lam.checkpoint_durable_execution(
            DurableExecutionArn=arn, CheckpointToken="sim2real-behav-synthetic-token", Updates=[]
        )
    )
    # A synthetic token is rejected with ValidationException before KMS is consulted.
    assert checkpoint_code in kms_codes + ("ValidationException",), (
        f"CheckpointDurableExecution: expected a KMS-family/validation error, got {checkpoint_code}"
    )

    try:
        lam.stop_durable_execution(DurableExecutionArn=arn)
        stop_code = None
    except ClientError as exc:
        stop_code = exc.response.get("Error", {}).get("Code")
    assert stop_code is None or stop_code in kms_codes + ("ResourceConflictException", "InvalidParameterValueException"), (
        f"StopDurableExecution: expected success or a KMS-family/conflict error, got {stop_code}"
    )


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
