"""describe-state-machine-kms-invalid-state."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-state-machine-kms-invalid-state"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD", **kwargs):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=[{"key": "sim2real-behav-check", "value": CHECK}],
        **kwargs,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _create_kms_key(ctx, description="sim2real-behav sfn test key"):
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description=description,
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return resp["KeyMetadata"]


def _disable_kms_key(ctx, key_id, *, timeout_s=60):
    kms = ctx.client("kms")
    kms.disable_key(KeyId=key_id)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "Disabled":
            return
        time.sleep(2)
    raise AssertionError(f"KMS key {key_id} did not reach Disabled state within {timeout_s}s")


def _enable_kms_key(ctx, key_id, *, timeout_s=60):
    kms = ctx.client("kms")
    kms.enable_key(KeyId=key_id)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "Enabled":
            return
        time.sleep(2)
    raise AssertionError(f"KMS key {key_id} did not reach Enabled state within {timeout_s}s")


# The relayed KMS message ends with the inner KMS call's request id and the SDK attempt count;
# those are the only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message):
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachine on a machine whose customer-managed KMS key is disabled raises
    KmsInvalidStateException rather than serving a cached definition, and succeeds again once the
    key is re-enabled.
    """
    sfn = ctx.client("stepfunctions")
    key = _create_kms_key(ctx)
    key_arn = key["Arn"]
    reuse_period = 60
    arn = _create_state_machine(
        ctx,
        _asl_pass({"ok": True}),
        encryptionConfiguration={
            "type": "CUSTOMER_MANAGED_KMS_KEY",
            "kmsKeyId": key_arn,
            "kmsDataKeyReusePeriodSeconds": reuse_period,
        },
    )

    # Sanity: Describe succeeds normally while the key is still enabled.
    before = sfn.describe_state_machine(stateMachineArn=arn)
    assert before["stateMachineArn"] == arn, f"expected a normal describe before disabling the key, got {before}"

    _disable_kms_key(ctx, key["KeyId"])

    # DescribeStateMachine may still be serving a cached plaintext data key
    # negotiated before the key was disabled, so poll rather than assume the
    # reuse window's worth of wall clock is itself sufficient.
    code = message = last_success = None
    poll_deadline = time.monotonic() + reuse_period + 15 + 60
    while time.monotonic() < poll_deadline:
        try:
            last_success = sfn.describe_state_machine(stateMachineArn=arn)
            code = None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            if code == "KmsInvalidStateException":
                break
        time.sleep(3)
    if code is None:
        raise AssertionError(
            f"expected KmsInvalidStateException, describe still succeeds with the key disabled: {last_success!r}"
        )
    assert code == "KmsInvalidStateException", f"expected KmsInvalidStateException, got {code!r}"
    # AWS appends the inner KMS call's request id and SDK attempt count to the key-disabled text.
    expected = (
        f"{key_arn} is disabled. (Service: Kms, Status Code: 400, Request ID: <request-id>) "
        "(SDK Attempt Count: <n>)"
    )
    assert _stable(message) == expected, f"expected message {expected!r}, got {message!r}"

    # Restore: re-enable the key and demand the identical describe succeed again,
    # proving the block tracked live key state rather than latching permanently.
    _enable_kms_key(ctx, key["KeyId"])

    after = None
    restore_deadline = time.monotonic() + reuse_period + 15 + 60
    while time.monotonic() < restore_deadline:
        try:
            after = sfn.describe_state_machine(stateMachineArn=arn)
            break
        except ClientError as exc:
            after = exc.response.get("Error", {}).get("Code")
            time.sleep(3)
    assert (
        isinstance(after, dict) and after["stateMachineArn"] == arn
    ), f"expected the identical describe to succeed again after re-enabling the key, got {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
