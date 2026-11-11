"""xsvc-sfn-kms-access-denied-mid-execution-fails-states-runtime."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-kms-access-denied-mid-execution-fails-states-runtime"
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


# timing:real-time — workflow: 240 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "cap:c4", "concern:negative-classes",
      "timing:real-time")
def run(ctx) -> None:
    """Denying the execution role's kms:Decrypt on a state machine's CMK while an execution is
    inside a Wait state fails that execution States.Runtime, cause naming the role and the key,
    once the Wait period elapses and Step Functions can no longer decrypt the data key.
    """
    sfn = ctx.client("stepfunctions")
    key = _key(ctx)
    role_name, role_arn = _exec_role(ctx, key["Arn"])
    _grant_kms_crypto_access(ctx, key["KeyId"], role_arn)
    sm_arn = _state_machine(ctx, role_arn, key["Arn"])

    arn = _start(ctx, sm_arn, json.dumps({"probe": ctx.unique_name("sim2real-mark-")}))
    _wait_for_event(ctx, arn, "WaitStateEntered")

    _revoke_kms_crypto_access(ctx, key["KeyId"])

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
        "an execution whose execution role has lost kms:Decrypt when its Wait state ends must "
        f"FAIL; got {status!r} within {_WAIT_S + 120}s")

    # error/cause are sensitive fields elided by METADATA_ONLY, so read them back only once the
    # grant is restored.
    _grant_kms_crypto_access(ctx, key["KeyId"], role_arn)
    deadline = time.monotonic() + _REUSE_S + 120.0
    full = None
    while time.monotonic() < deadline:
        try:
            full = sfn.describe_execution(executionArn=arn, includedData="ALL_DATA")
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException":
                raise
            time.sleep(3.0)
    assert full is not None, (
        f"ALL_DATA DescribeExecution was still KmsAccessDeniedException {_REUSE_S + 120}s after "
        "the grant was restored")
    assert full["status"] == "FAILED", f"status must still be FAILED after restore; got {full['status']!r}"
    assert full["error"] == "States.Runtime", (
        f"a mid-execution KMS-denied failure must carry error States.Runtime; got {full['error']!r}")
    stabilized = _stable_session(_stable(full.get("cause")), role_name)
    expected_cause = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/<session> is not authorized "
        f"to perform: kms:Decrypt on resource: {key['Arn']} with an explicit deny in a "
        "resource-based policy (Service: Kms, Status Code: 400, Request ID: <request-id>) "
        "(SDK Attempt Count: <n>)"
    )
    assert stabilized == expected_cause, f"expected cause {expected_cause!r}, got {full.get('cause')!r}"


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# Longer than the deny's propagation poll (up to 90 s) plus the data-key reuse period (60 s), so
# the deny is in effect and no cached data key remains when the Wait ends.
_WAIT_S = 240

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


def _exec_role(ctx, key_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfn-kms-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn CMK execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


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


def _grant_kms_crypto_access(ctx, key_id: str, role_arn: str) -> None:
    """Grant the key policy to ALLOW the execution role's data-key and decrypt operations,
    alongside root management access. Step Functions assumes this role to call KMS on the
    check's behalf, so this is what makes StartExecution itself possible."""
    kms = ctx.client("kms")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowExecutionRoleCrypto",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    }
    # The key policy above names role_arn, a role created moments ago -- KMS validates every
    # policy principal against IAM at write time and returns MalformedPolicyDocumentException
    # ("invalid principals") until that role has propagated to where KMS's validator can see it.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))
            return
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "MalformedPolicyDocumentException"
                    or time.monotonic() > deadline):
                raise
            time.sleep(3.0)


def _revoke_kms_crypto_access(ctx, key_id: str, *, timeout_s: float = 90.0) -> None:
    """Overwrite the key policy to explicitly DENY all crypto operations to every principal, while
    leaving management actions allowed to the account root so cleanup can still schedule deletion.
    Then poll a harmless GenerateDataKey call until the deny is actually enforced."""
    kms = ctx.client("kms")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "DenyCryptoOperations",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncryptFrom",
                    "kms:ReEncryptTo",
                    "kms:GenerateDataKey",
                    "kms:GenerateDataKeyWithoutPlaintext",
                ],
                "Resource": "*",
            },
        ],
    }
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "AccessDeniedException":
                return
        time.sleep(3.0)
    raise AssertionError("KMS deny-crypto key policy did not propagate in time")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
