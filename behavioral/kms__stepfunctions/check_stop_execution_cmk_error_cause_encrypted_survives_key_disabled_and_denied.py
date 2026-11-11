"""stop-execution-cmk-error-cause-encrypted-survives-key-disabled-and-denied."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-execution-cmk-error-cause-encrypted-survives-key-disabled-and-denied"
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


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html
@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:e2e", "concern:negative-classes",
      "timing:real-time")
def run(ctx) -> None:
    """StopExecution on a CMK execution stores its error/cause encrypted and reads them back;
    a disabled key then refuses DescribeExecution KmsInvalidState, a denying key policy
    refuses it KmsAccessDenied, and once both are restored it again reads ABORTED unchanged.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")
    key = _key(ctx)
    role_name, role_arn = _exec_role(ctx, key["Arn"])
    act = _activity(ctx)
    definition = json.dumps({
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": act, "TimeoutSeconds": 1200, "End": True}},
    })
    sm_arn = _state_machine(ctx, role_arn, key["Arn"], definition)

    _marker, payload = _payload(ctx)
    exec_arn = _start(ctx, sm_arn, payload)
    _poll_activity_task(ctx, act)

    stop_error, stop_cause = "sim2real-stop-error", "sim2real-stop-cause: ünïcode ✓"
    sfn.stop_execution(executionArn=exec_arn, error=stop_error, cause=stop_cause)
    stopped = _wait_terminal(ctx, exec_arn)
    assert stopped["status"] == "ABORTED", f"StopExecution must leave the status ABORTED; got {stopped['status']!r}"
    assert stopped.get("error") == stop_error and stopped.get("cause") == stop_cause, (
        f"DescribeExecution must read the stop error/cause back exactly; got "
        f"error={stopped.get('error')!r} cause={stopped.get('cause')!r}")
    hist = _history(ctx, exec_arn)
    aborted = [h for h in hist if h["type"] == "ExecutionAborted"]
    assert len(aborted) == 1, f"expected exactly one ExecutionAborted event; got {aborted!r}"
    details = aborted[0]["executionAbortedEventDetails"]
    assert details.get("error") == stop_error and details.get("cause") == stop_cause, (
        f"GetExecutionHistory's ExecutionAborted must carry the same error/cause; got {details!r}")

    kms.disable_key(KeyId=key["KeyId"])
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key["KeyId"]))
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the key Disabled; it is {state!r}"
    # A read made right after DisableKey can still be served from a data key Step Functions
    # cached before it, within the reuse window; poll the (side-effect-free) read itself until it
    # is refused, bounded by that window plus margin.
    code, message = _refusal_within(lambda: sfn.describe_execution(executionArn=exec_arn), 150.0)
    assert code == "KmsInvalidStateException", (
        f"DescribeExecution on an ABORTED execution whose CMK is Disabled must be refused "
        f"KmsInvalidStateException; got {code!r}: {message!r}")
    expected = (
        f"{key['Arn']} is disabled. (Service: Kms, Status Code: 400, "
        "Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    assert _stable(message) == expected, f"expected message {expected!r}; got {message!r}"

    kms.enable_key(KeyId=key["KeyId"])
    _wait_describe_recovers(ctx, exec_arn)

    # DescribeExecution decrypts as the API CALLER, not as the execution role: Step Functions
    # only assumes the execution role for the calls it makes on the workflow's own behalf
    # (StartExecution, SendTaskSuccess/Failure). A key-policy deny is what a read observes.
    allow_policy = _key_policy(ctx, key["KeyId"])
    _deny_all_crypto(ctx, key["KeyId"], allow_policy)
    # A read made right after the deny can still be served from a data key Step Functions
    # cached before it, within the reuse window; poll the (side-effect-free) read itself
    # until it is refused, bounded by that window plus margin.
    code, message = _refusal_within(lambda: sfn.describe_execution(executionArn=exec_arn), 150.0)
    assert code == "KmsAccessDeniedException", (
        f"DescribeExecution once the key's policy denies every principal must be refused "
        f"KmsAccessDeniedException; got {code!r}: {message!r}")
    expected = _kms_access_denied_message(ctx, key["Arn"])
    assert _stable(message) == expected, f"expected message {expected!r}; got {message!r}"

    kms.put_key_policy(KeyId=key["KeyId"], PolicyName="default", Policy=json.dumps(allow_policy))
    deadline = time.monotonic() + 240.0
    restored = None
    last = None
    while time.monotonic() < deadline:
        try:
            restored = sfn.describe_execution(executionArn=exec_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException":
                raise
            last = exc
            time.sleep(3.0)
    assert restored is not None, (
        f"DescribeExecution still KmsAccessDenied 240s after repairing the key policy: {last}")
    assert restored["status"] == "ABORTED", (
        f"once the key policy is repaired, status must read ABORTED again; "
        f"got {restored['status']!r}")
    assert restored.get("error") == stop_error and restored.get("cause") == stop_cause, (
        f"the stop error/cause must read back unchanged; got error={restored.get('error')!r} "
        f"cause={restored.get('cause')!r}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-behav {CHECK[:180]}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _exec_role(ctx, key_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnkms4-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real: sfn CMK execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="kms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
             "Resource": key_arn}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="kms"))
    return name, arn


def _activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnkms4-")[:80]
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": CHECK[:250]}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _state_machine(ctx, role_arn: str, key_arn: str, definition: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnkms4-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                encryptionConfiguration={
                    "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
                    "kmsDataKeyReusePeriodSeconds": 60,
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
    trust and KMS grants propagate."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 150.0
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
        f"StartExecution still KmsAccessDenied 150s after the execution role (which holds "
        f"kms:GenerateDataKey and kms:Decrypt) was created: {last}")


def _refusal_within(fn, timeout_s: float) -> tuple[str, str | None]:
    """(code, message) of the first ClientError fn raises, polling while it still succeeds;
    raises AssertionError if it still succeeds at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() > deadline:
            raise AssertionError(f"the read still succeeds {timeout_s}s after the key change")
        time.sleep(3.0)


def _wait_describe_recovers(ctx, arn: str) -> None:
    """Poll DescribeExecution until it stops raising KmsInvalidStateException, so the next
    mutation never races EnableKey's propagation to the crypto path."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 240.0
    last = None
    while time.monotonic() < deadline:
        try:
            sfn.describe_execution(executionArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsInvalidStateException":
                raise
            last = exc
            time.sleep(5.0)
    raise AssertionError(f"DescribeExecution still KmsInvalidState 240s after EnableKey: {last}")


def _stop_if_running(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_terminal(ctx, arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 60.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} still RUNNING after 60s: {last!r}")


def _history(ctx, arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    out, kwargs = [], {"executionArn": arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


def _poll_activity_task(ctx, activity_arn: str, *, timeout_s: float = 65.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn)
        if resp.get("taskToken"):
            return resp
        time.sleep(0.5)
    raise AssertionError(f"no activity task scheduled within {timeout_s}s")


def _key_policy(ctx, key_id: str) -> dict:
    return json.loads(ctx.client("kms").get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])


def _deny_all_crypto(ctx, key_id: str, allow_policy: dict) -> None:
    """Overwrite the key policy so every principal (ours included) is denied crypto, keeping
    account-root management access so cleanup still works; register the restore immediately so
    a later failure never leaves the account with a key every read is denied against, and poll
    a caller-side GenerateDataKey until the deny is actually enforced."""
    kms = ctx.client("kms")
    denying = json.loads(json.dumps(allow_policy))
    denying["Statement"].append({
        "Sid": "DenyAllCrypto", "Effect": "Deny", "Principal": {"AWS": "*"},
        "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo",
                   "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext"],
        "Resource": "*",
    })
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(denying))
    ctx.on_cleanup(lambda: kms.put_key_policy(
        KeyId=key_id, PolicyName="default", Policy=json.dumps(allow_policy)))
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                return
            raise
        time.sleep(3.0)
    raise AssertionError("KMS deny-all-crypto key policy did not propagate in time")


def _kms_access_denied_message(ctx, key_arn: str) -> str:
    """The exact text Step Functions relays for a key-policy explicit deny on a read: the
    caller's own identity is this check's session; request id and attempt count are masked."""
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    return (
        f"User: {caller_arn} is not authorized to perform: kms:Decrypt on resource: {key_arn} "
        f"with an explicit deny in a resource-based policy (Service: Kms, Status Code: 400, "
        "Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )


def _payload(ctx) -> tuple[str, str]:
    marker = ctx.unique_name("sim2real-mark-")
    return marker, json.dumps({"marker": marker})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
