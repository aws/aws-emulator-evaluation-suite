"""xsvc-sfn-disabled-cmk-mid-execution-fails-states-runtime."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-disabled-cmk-mid-execution-fails-states-runtime"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

# The relayed KMS message ends with the inner KMS call's request id and the SDK attempt count;
# those are the only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message: str | None) -> str | None:
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


# timing:real-time — workflow: 75 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "cap:c4", "concern:negative-classes",
      "timing:real-time")
def run(ctx) -> None:
    """Disabling a state machine's CMK while an execution is RUNNING inside a Wait state fails
    that execution States.Runtime, with the cause naming the disabled key, once the Wait period
    elapses and Step Functions can no longer access the data key to record the transition.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")
    key = _key(ctx)
    _role_name, role_arn = _exec_role(ctx, key["Arn"], ["kms:Decrypt", "kms:GenerateDataKey"])
    sm_arn = _state_machine(ctx, role_arn, key["Arn"])

    arn = _start(ctx, sm_arn, json.dumps({"probe": ctx.unique_name("sim2real-mark-")}))
    _wait_for_event(ctx, arn, "WaitStateEntered")

    kms.disable_key(KeyId=key["KeyId"])
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key["KeyId"]))
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the key Disabled; it is {state!r}"

    # The Wait state ends at _WAIT_S, and reads an elided status without needing KMS at all
    # (includedData=METADATA_ONLY), so the execution itself must leave RUNNING once that elapses.
    deadline = time.monotonic() + _WAIT_S + 120.0
    status = None
    while time.monotonic() < deadline:
        status = sfn.describe_execution(executionArn=arn, includedData="METADATA_ONLY")["status"]
        if status != "RUNNING":
            break
        time.sleep(3.0)
    assert status == "FAILED", (
        f"an execution whose CMK is Disabled when its Wait state ends must FAIL; got {status!r} "
        f"within {_WAIT_S + 120}s")

    # error/cause are sensitive fields elided by METADATA_ONLY, so read them back only once the
    # key is usable again.
    kms.enable_key(KeyId=key["KeyId"])
    deadline = time.monotonic() + _REUSE_S + 120.0
    full = None
    while time.monotonic() < deadline:
        try:
            full = sfn.describe_execution(executionArn=arn, includedData="ALL_DATA")
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsInvalidStateException":
                raise
            time.sleep(3.0)
    assert full is not None, (
        f"ALL_DATA DescribeExecution was still KmsInvalidStateException {_REUSE_S + 120}s after "
        "EnableKey")
    assert full["status"] == "FAILED", f"status must still be FAILED after re-enable; got {full['status']!r}"
    assert full["error"] == "States.Runtime", (
        f"a mid-execution disabled-CMK failure must carry error States.Runtime; got {full['error']!r}")
    expected_cause = _kms_disabled_message(key["Arn"])
    assert _stable(full["cause"]) == expected_cause, (
        f"expected cause {expected_cause!r}, got {full.get('cause')!r}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# Long enough for a disable made right after entry to still be in effect when the Wait ends,
# short enough to keep the check's wall-clock bounded.
_WAIT_S = 75

_DEFINITION = json.dumps({
    "StartAt": "W",
    "States": {"W": {"Type": "Wait", "Seconds": _WAIT_S, "End": True}},
})

# StartExecution on a CMK-encrypted machine calls KMS as the execution role; until the role's
# trust propagates (~35s after CreateRole) it fails KmsAccessDeniedException, and IAM exposes
# no condition to poll.
_ROLE_PROPAGATION_S = 150.0

# The minimum reuse period: how long Step Functions may serve a cached data key.
_REUSE_S = 60


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-xsvc-sfn {CHECK[:200]}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _exec_role(ctx, key_arn: str, kms_actions: list[str]) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfn-kms-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn CMK execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    _put_kms_policy(ctx, name, key_arn, kms_actions)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="kms"))
    return name, arn


def _put_kms_policy(ctx, role_name: str, key_arn: str, kms_actions: list[str]) -> None:
    ctx.client("iam").put_role_policy(
        RoleName=role_name, PolicyName="kms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": kms_actions, "Resource": key_arn}]}),
    )


def _state_machine(ctx, role_arn: str, key_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfn-kms-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="STANDARD",
                encryptionConfiguration={
                    "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
                    "kmsDataKeyReusePeriodSeconds": _REUSE_S,
                },
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


def _start(ctx, sm_arn: str, payload: str) -> str:
    """StartExecution, retrying only KmsAccessDeniedException while the execution role's
    trust propagates (see _ROLE_PROPAGATION_S)."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.start_execution(stateMachineArn=sm_arn, input=payload)["executionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException":
                raise
            last = exc
            time.sleep(4.0)
            continue
        ctx.on_cleanup(lambda: _stop_if_running(sfn, arn))
        return arn
    raise AssertionError(
        f"StartExecution still KmsAccessDenied {_ROLE_PROPAGATION_S}s after the execution "
        f"role (which holds kms:GenerateDataKey and kms:Decrypt) was created: {last}")


def _stop_if_running(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn, includedData="METADATA_ONLY")["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_for_event(ctx, arn: str, event_type: str, *, timeout_s: float = 30.0) -> None:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    types: list[str] = []
    while time.monotonic() < deadline:
        types = [e["type"] for e in
                 sfn.get_execution_history(executionArn=arn, maxResults=20)["events"]]
        if event_type in types:
            return
        time.sleep(1.0)
    raise AssertionError(f"{event_type} not observed within {timeout_s}s; saw {types}")


def _kms_disabled_message(key_arn: str) -> str:
    """The exact text Step Functions relays from KMS for a disabled key, request id and attempt
    count masked."""
    return (
        f"{key_arn} is disabled. (Service: Kms, Status Code: 400, Request ID: <request-id>) "
        "(SDK Attempt Count: <n>)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
