"""xsvc-sfn-get-execution-history-kms-deny-refuses-even-without-execution-data."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-get-execution-history-kms-deny-refuses-even-without-execution-data"
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


_EVENT_DATA_KEYS = {
    "executionStartedEventDetails": ("input",),
    "executionSucceededEventDetails": ("output",),
    "stateEnteredEventDetails": ("input",),
    "stateExitedEventDetails": ("output",),
}


def _data_fields_present(event: dict) -> list[str]:
    present = []
    for details_key, fields in _EVENT_DATA_KEYS.items():
        details = event.get(details_key)
        if not details:
            continue
        for field in fields:
            if field in details:
                present.append(f"{details_key}.{field}")
    return present


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html
@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:data-plane",
      "concern:negative-classes", "timing:real-time")
def run(ctx) -> None:
    """GetExecutionHistory on a CMK-encrypted execution is refused KmsAccessDeniedException once
    the key denies crypto access, with includeExecutionData=False too (unlike DescribeExecution's
    METADATA_ONLY), which elides every input/output field while the key allows the read.
    """
    sfn = ctx.client("stepfunctions")
    key = _key(ctx)
    _role_name, role_arn = _exec_role(ctx, key["Arn"], ["kms:Decrypt", "kms:GenerateDataKey"])
    sm_arn = _state_machine(ctx, role_arn, key["Arn"])

    _marker, payload = _payload(ctx)
    arn = _start(ctx, sm_arn, payload)
    before = _wait_terminal(ctx, arn)
    assert before["status"] == "SUCCEEDED", (
        f"the execution must SUCCEED before the key is touched; got {before['status']!r}")

    full = _history(ctx, arn, include_execution_data=True)
    types = [e["type"] for e in full]
    assert types == [
        "ExecutionStarted", "PassStateEntered", "PassStateExited", "PassStateEntered",
        "PassStateExited", "ExecutionSucceeded",
    ], f"positive control: unexpected event type sequence {types}"
    started = next(e for e in full if e["type"] == "ExecutionStarted")
    assert started["executionStartedEventDetails"]["input"] == payload, (
        "positive control: ExecutionStarted must carry the sent input; got "
        f"{started['executionStartedEventDetails'].get('input')!r}")
    with_data = sum(len(_data_fields_present(e)) for e in full)
    assert with_data > 0, "positive control: includeExecutionData=True must carry input/output"

    elided_before = _history(ctx, arn, include_execution_data=False, max_results=1)
    assert [e["type"] for e in elided_before] == types, (
        "includeExecutionData=False under maxResults=1 must return the same event sequence as "
        f"the full read; got {[e['type'] for e in elided_before]}")
    leaked = [f for e in elided_before for f in _data_fields_present(e)]
    assert leaked == [], (
        f"includeExecutionData=False must elide every input/output field; still present: {leaked}")

    _revoke_kms_crypto_access(ctx, key["KeyId"])

    # A cached data key may legitimately serve a decrypting read for up to the reuse period, so
    # poll for the refusal with a deadline of that period plus slack, never a fixed sleep.
    deadline = time.monotonic() + _REUSE_S + 90.0
    code = msg = None
    while time.monotonic() < deadline:
        try:
            sfn.get_execution_history(executionArn=arn)
        except ClientError as exc:
            code, msg = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
            break
        time.sleep(3.0)
    assert code == "KmsAccessDeniedException", (
        f"GetExecutionHistory with execution data under a key denying crypto access must raise "
        f"KmsAccessDeniedException within {_REUSE_S}s reuse + 90s; got {code!r}")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected_msg = (
        f"User: {caller_arn} is not authorized to perform: kms:Decrypt on resource: "
        f"{key['Arn']} with an explicit deny in a resource-based policy (Service: Kms, "
        "Status Code: 400, Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    assert _stable(msg) == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Unlike DescribeExecution's includedData=METADATA_ONLY (which never calls KMS),
    # includeExecutionData=False still needs the decrypt that just failed: it elides the payload
    # fields after decrypting the stored history, so it is refused exactly the same way.
    elided_code, elided_msg = _error(
        lambda: sfn.get_execution_history(executionArn=arn, includeExecutionData=False,
                                           maxResults=1))
    assert elided_code == "KmsAccessDeniedException", (
        "includeExecutionData=False must be refused the same way as a full read once the key "
        f"denies crypto access, since it still decrypts the stored history; got {elided_code!r}")
    assert _stable(elided_msg) == expected_msg, (
        f"expected message {expected_msg!r}, got {elided_msg!r}")

    _grant_kms_crypto_access(ctx, key["KeyId"], role_arn)
    deadline = time.monotonic() + _REUSE_S + 120.0
    restored = None
    while time.monotonic() < deadline:
        try:
            restored = _history(ctx, arn, include_execution_data=True)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException":
                raise
            time.sleep(3.0)
    assert restored is not None, (
        f"GetExecutionHistory with execution data was still KmsAccessDeniedException "
        f"{_REUSE_S + 120}s after the grant was restored -- the refusal latched instead of "
        "tracking the key policy")
    restored_started = next(e for e in restored if e["type"] == "ExecutionStarted")
    assert restored_started["executionStartedEventDetails"]["input"] == payload, (
        "after the grant is restored, the full read must carry the input again; got "
        f"{restored_started['executionStartedEventDetails'].get('input')!r}")

    elided_after = _history(ctx, arn, include_execution_data=False, max_results=1)
    assert [e["type"] for e in elided_after] == types, (
        "after the grant is restored, includeExecutionData=False must again return every event; "
        f"got {[e['type'] for e in elided_after]}")
    leaked = [f for e in elided_after for f in _data_fields_present(e)]
    assert leaked == [], (
        f"after the grant is restored, includeExecutionData=False must still elide every field; "
        f"still present: {leaked}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# Two Pass states chained so ExecutionStarted/StateEntered/StateExited/ExecutionSucceeded each
# carry a distinct input/output payload to check for elision. Each carries marker.$ forward so
# the second state's input still has it (a state's input is the prior state's full output).
_DEFINITION = json.dumps({
    "StartAt": "A",
    "States": {
        "A": {"Type": "Pass", "Parameters": {"step": "A", "marker.$": "$.marker"}, "Next": "B"},
        "B": {"Type": "Pass", "Parameters": {"step": "B", "marker.$": "$.marker"}, "End": True},
    },
})

# StartExecution on a CMK-encrypted machine calls KMS as the execution role; until the role's
# trust propagates (~35s after CreateRole) it fails KmsAccessDeniedException, and IAM exposes
# no condition to poll.
_ROLE_PROPAGATION_S = 150.0


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


# The minimum reuse period: how long Step Functions may serve a cached data key.
_REUSE_S = 60


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


def _wait_terminal(ctx, arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} still RUNNING after 120s (two Pass states): {last!r}")


def _history(ctx, arn: str, *, include_execution_data: bool, max_results: int = 1000) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    out = []
    kwargs = {"executionArn": arn, "maxResults": max_results,
              "includeExecutionData": include_execution_data}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


def _error(fn) -> tuple[str, str | None]:
    """(code, message) of the ClientError fn raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _revoke_kms_crypto_access(ctx, key_id: str, *, timeout_s: float = 90.0) -> None:
    """Overwrite the key policy to explicitly DENY all crypto operations to every principal, while
    leaving management actions allowed to the account root so cleanup can still schedule deletion,
    and register the restore of the prior policy right away. Then poll a harmless GenerateDataKey
    call until the deny is actually enforced."""
    kms = ctx.client("kms")
    prior = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
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
    ctx.on_cleanup(lambda: kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=prior))

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                return
            raise
        time.sleep(3.0)
    raise AssertionError("KMS deny-crypto key policy did not propagate in time")


def _grant_kms_crypto_access(ctx, key_id: str, role_arn: str) -> None:
    """Restore the key policy to ALLOW the execution role's data-key and decrypt operations,
    alongside root management access."""
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
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))


def _payload(ctx) -> tuple[str, str]:
    marker = ctx.unique_name("sim2real-mark-")
    return marker, json.dumps({"marker": marker})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
