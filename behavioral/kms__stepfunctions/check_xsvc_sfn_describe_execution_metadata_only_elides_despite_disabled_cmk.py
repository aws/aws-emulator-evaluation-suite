"""xsvc-sfn-describe-execution-metadata-only-elides-despite-disabled-cmk."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-describe-execution-metadata-only-elides-despite-disabled-cmk"
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
@tags("axis:happy-path", "dp:api", "plane:data", "cap:c3", "concern:data-plane", "timing:real-time")
def run(ctx) -> None:
    """DescribeExecution with includedData=METADATA_ONLY on a CMK-encrypted execution returns
    status and metadata with input/output elided, and keeps doing so once the CMK is disabled
    and ALL_DATA reads are refused KmsInvalidStateException -- it never attempts a decrypt.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")
    key = _key(ctx)
    _role_name, role_arn = _exec_role(ctx, key["Arn"], ["kms:Decrypt", "kms:GenerateDataKey"])
    sm_arn = _state_machine(ctx, role_arn, key["Arn"])

    _marker, payload = _payload(ctx)
    arn = _start(ctx, sm_arn, payload)
    before = _wait_terminal(ctx, arn)
    assert before["status"] == "SUCCEEDED", (
        f"the execution must SUCCEED before the key is touched; got {before['status']!r}")
    assert before["input"] == payload, f"positive control: input read back {before['input']!r}"

    meta_before = sfn.describe_execution(executionArn=arn, includedData="METADATA_ONLY")
    assert meta_before["status"] == "SUCCEEDED", (
        f"METADATA_ONLY must still report the execution's status; got {meta_before['status']!r}")
    assert "input" not in meta_before and "output" not in meta_before, (
        "METADATA_ONLY must elide input/output while the key is healthy; got keys "
        f"{sorted(meta_before.keys())!r}")

    kms.disable_key(KeyId=key["KeyId"])
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key["KeyId"]))
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the key Disabled; it is {state!r}"

    # A cached data key may legitimately serve ALL_DATA reads for up to the reuse period, so poll
    # for the refusal with a deadline of that period plus slack, never a fixed sleep.
    deadline = time.monotonic() + _REUSE_S + 90.0
    all_data_code = all_data_msg = None
    while time.monotonic() < deadline:
        try:
            sfn.describe_execution(executionArn=arn, includedData="ALL_DATA")
        except ClientError as exc:
            all_data_code = exc.response["Error"]["Code"]
            all_data_msg = exc.response["Error"].get("Message")
            break
        time.sleep(3.0)
    assert all_data_code == "KmsInvalidStateException", (
        f"ALL_DATA DescribeExecution under a Disabled CMK must raise KmsInvalidStateException "
        f"within {_REUSE_S}s reuse + 90s; got {all_data_code!r}")
    expected = (
        f"{key['Arn']} is disabled. (Service: Kms, Status Code: 400, Request ID: <request-id>) "
        "(SDK Attempt Count: <n>)"
    )
    assert _stable(all_data_msg) == expected, (
        f"DescribeExecution must relay KMS's disabled-key message {expected!r}; got {all_data_msg!r}")

    # Now that ALL_DATA is confirmed refused, METADATA_ONLY on the very same execution must still
    # succeed: it elides input/output instead of attempting the decrypt that just failed.
    meta_during = sfn.describe_execution(executionArn=arn, includedData="METADATA_ONLY")
    assert meta_during["status"] == "SUCCEEDED", (
        "METADATA_ONLY must succeed even while the CMK is Disabled; got "
        f"{meta_during!r}")
    assert "input" not in meta_during and "output" not in meta_during, (
        "METADATA_ONLY under a Disabled CMK must still elide input/output rather than surface "
        f"the KMS failure; got keys {sorted(meta_during.keys())!r}")
    for field in ("executionArn", "stateMachineArn", "name", "startDate", "stopDate"):
        assert meta_during.get(field) == before.get(field), (
            f"METADATA_ONLY must report the same {field!r} as a healthy read; got "
            f"{meta_during.get(field)!r} vs {before.get(field)!r}")

    kms.enable_key(KeyId=key["KeyId"])
    deadline = time.monotonic() + _REUSE_S + 120.0
    after = None
    while time.monotonic() < deadline:
        try:
            after = sfn.describe_execution(executionArn=arn, includedData="ALL_DATA")
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsInvalidStateException":
                raise
            time.sleep(3.0)
    assert after is not None, (
        f"ALL_DATA DescribeExecution was still KmsInvalidStateException {_REUSE_S + 120}s after "
        "EnableKey -- the refusal latched instead of tracking the key state")
    assert after["input"] == payload and after["output"] == before["output"], (
        "after re-enable ALL_DATA must read back unchanged: input "
        f"{after.get('input')!r} output {after.get('output')!r} vs before {before['output']!r}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# Pass state that reshapes the input, so the output is execution data derived from it.
_DEFINITION = json.dumps({
    "StartAt": "Shape",
    "States": {
        "Shape": {
            "Type": "Pass",
            "Parameters": {"echo.$": "$.marker", "items.$": "$.items", "fixed": 7},
            "End": True,
        },
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
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
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
    raise AssertionError(f"execution {arn} still RUNNING after 120s (a single Pass): {last!r}")


def _payload(ctx) -> tuple[str, str]:
    marker = ctx.unique_name("sim2real-mark-")
    return marker, json.dumps({"marker": marker, "items": [1, "two", {"three": 3.5}],
                               "note": "ünïcode ✓"})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
