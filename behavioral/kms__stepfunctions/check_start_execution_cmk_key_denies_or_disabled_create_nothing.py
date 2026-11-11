"""start-execution-cmk-key-denies-or-disabled-create-nothing."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-execution-cmk-key-denies-or-disabled-create-nothing"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

# The relayed KMS message ends with the inner KMS call's request id and the SDK attempt count,
# and names the execution role's per-session name Step Functions mints at random; those are the
# only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message: str | None) -> str | None:
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


def _stable_session(message: str | None, role_name: str) -> str | None:
    if message is None:
        return None
    pattern = re.compile(rf"(assumed-role/{re.escape(role_name)}/)[^ ]+")
    return pattern.sub(r"\1<session>", message, count=1)


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html
@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:e2e", "concern:negative-classes",
      "timing:real-time")
def run(ctx) -> None:
    """StartExecution on a CMK machine is refused synchronously and creates no execution:
    KmsAccessDeniedException once the key's policy denies every principal, and
    KmsInvalidStateException once the key is disabled; a twin execution still succeeds.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")
    key = _key(ctx)
    role_name, role_arn = _exec_role(ctx, key["Arn"])
    sm_arn = _state_machine(ctx, role_arn, key["Arn"])

    _marker, payload = _payload(ctx)
    control_arn = _start(ctx, sm_arn, payload)
    control = _wait_terminal(ctx, control_arn)
    assert control["status"] == "SUCCEEDED", (
        f"control: a CMK execution through a role with Decrypt+GenerateDataKey and a "
        f"non-denying key policy must SUCCEED; got {control['status']!r}")

    allow_policy = _key_policy(ctx, key["KeyId"])
    _deny_all_crypto(ctx, key["KeyId"], allow_policy)
    # The reuse period lets Step Functions keep encrypting NEW executions with a data key it
    # already cached from the control run, so the deny is only guaranteed visible after it
    # elapses; a single determinative call follows, never a retry that could itself succeed
    # and create an execution.
    # fixed-wait: no API reports when Step Functions' cached data key (60 s reuse period) expires
    time.sleep(150)
    code, message = _start_once(ctx, sm_arn, payload)
    assert code == "KmsAccessDeniedException", (
        f"StartExecution on a machine whose CMK policy denies every principal must be refused "
        f"KmsAccessDeniedException; got {code!r}: {message!r}")
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/<session> is not authorized "
        f"to perform: kms:GenerateDataKey on resource: {key['Arn']} with an explicit deny in a "
        "resource-based policy (Service: Kms, Status Code: 400, Request ID: <request-id>) "
        "(SDK Attempt Count: <n>)"
    )
    assert _stable_session(_stable(message), role_name) == expected, (
        f"expected message {expected!r}; got {message!r}")
    listed = sorted(e["executionArn"] for e in sfn.list_executions(stateMachineArn=sm_arn)["executions"])
    assert listed == [control_arn], (
        f"a refused StartExecution must create no execution; ListExecutions shows {listed}, "
        f"expected only the control {control_arn!r}")

    kms.put_key_policy(KeyId=key["KeyId"], PolicyName="default", Policy=json.dumps(allow_policy))
    repaired_arn = _start(ctx, sm_arn, payload)
    repaired = _wait_terminal(ctx, repaired_arn)
    assert repaired["status"] == "SUCCEEDED", (
        f"once the key policy is repaired the same machine must SUCCEED again; "
        f"got {repaired['status']!r}")

    kms.disable_key(KeyId=key["KeyId"])
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key["KeyId"]))
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the key Disabled; it is {state!r}"
    # fixed-wait: no API reports when Step Functions' cached data key (60 s reuse period) expires
    time.sleep(150)
    code, message = _start_once(ctx, sm_arn, payload)
    assert code == "KmsInvalidStateException", (
        f"StartExecution on a machine whose CMK is Disabled must be refused "
        f"KmsInvalidStateException; got {code!r}: {message!r}")
    expected = (
        f"{key['Arn']} is disabled. (Service: Kms, Status Code: 400, "
        "Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    assert _stable(message) == expected, f"expected message {expected!r}; got {message!r}"
    listed = sorted(e["executionArn"] for e in sfn.list_executions(stateMachineArn=sm_arn)["executions"])
    assert listed == sorted([control_arn, repaired_arn]), (
        f"a refused StartExecution must create no execution; ListExecutions shows {listed}, "
        f"expected only {sorted([control_arn, repaired_arn])}")

    # Re-enable before cleanup reads either execution: EnableKey is eventually consistent for
    # the crypto path, so a teardown's DescribeExecution right after it can still see Disabled.
    kms.enable_key(KeyId=key["KeyId"])
    _wait_decrypt_recovers(ctx, control_arn)


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# Pass state that reshapes the input, so an execution's effect is observable beyond its status.
_DEFINITION = json.dumps({
    "StartAt": "Shape",
    "States": {"Shape": {"Type": "Pass", "Parameters": {"echo.$": "$.marker"}, "End": True}},
})

# The minimum reuse period: how long Step Functions may serve a cached data key, so a refusal
# caused by the key (rather than the role) is only guaranteed visible after this elapses.
_REUSE_S = 60


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
    name = ctx.unique_name("sim2real-behav-sfnkms-")[:64]
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


def _state_machine(ctx, role_arn: str, key_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnkms-")[:80]
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
    trust and KMS grant propagate. A retry here never masks a key-caused refusal: it is
    only ever used while the key policy allows the role."""
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


def _start_once(ctx, sm_arn: str, payload: str) -> tuple[str, str | None]:
    """Exactly one StartExecution: (code, message) of its refusal. Never retried, so an
    unexpected success is cleaned up and raised rather than hidden by a retry."""
    sfn = ctx.client("stepfunctions")
    try:
        arn = sfn.start_execution(stateMachineArn=sm_arn, input=payload)["executionArn"]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    ctx.on_cleanup(lambda: _stop_if_running(sfn, arn))
    raise AssertionError(f"expected StartExecution to be refused, but it started {arn!r}")


def _wait_decrypt_recovers(ctx, arn: str) -> None:
    """Poll DescribeExecution until it stops raising KmsInvalidStateException, so cleanup
    never races EnableKey's propagation to the crypto path."""
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
    raise AssertionError(f"execution {arn} still RUNNING after 60s (a single Pass): {last!r}")


def _key_policy(ctx, key_id: str) -> dict:
    return json.loads(ctx.client("kms").get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])


def _deny_all_crypto(ctx, key_id: str, allow_policy: dict) -> None:
    """Overwrite the key policy so every principal (ours included) is denied crypto, keeping
    account-root management access so cleanup still works; register the restore immediately so
    a later failure never leaves the account with a key every read is denied against, and poll
    a caller-side GenerateDataKey until the deny is actually enforced (propagation isn't
    instantaneous)."""
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


def _payload(ctx) -> tuple[str, str]:
    marker = ctx.unique_name("sim2real-mark-")
    return marker, json.dumps({"marker": marker})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
