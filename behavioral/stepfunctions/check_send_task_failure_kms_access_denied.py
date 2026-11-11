"""send-task-failure-kms-access-denied."""
from __future__ import annotations

import re
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-failure-kms-access-denied"
GROUP = 'activities'
SERVICES = ['stepfunctions']


# The relayed message ends with the inner call's request id and the SDK attempt count; those
# are the only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message):
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))
_SESSION = re.compile(r"(assumed-role/[^/ ]+/)[^ ]+ ")


_SFN_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_sfn_role(ctx, kms_key_arn=None):
    """An execution role this check creates, trusted by states.amazonaws.com, holding the
    data-key grants Step Functions needs on the state machine's customer-managed key."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_SFN_TRUST),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if kms_key_arn is not None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": kms_key_arn}
            ],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName="sfn-kms", PolicyDocument=json.dumps(policy))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-kms"))
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retrying AccessDeniedException while a fresh role's trust propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _account_id(ctx):
    return ctx.account


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD", encryption_configuration=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    kwargs = {
        "name": name,
        "definition": json.dumps(definition),
        "roleArn": _create_sfn_role(
            ctx, kms_key_arn=(encryption_configuration or {}).get("kmsKeyId")
        ),
        "type": sm_type,
    }
    if encryption_configuration is not None:
        kwargs["encryptionConfiguration"] = encryption_configuration
    arn = _create_sm_retrying(sfn, **kwargs)["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _create_activity(ctx, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return {"name": name, "arn": arn}


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    deadline = time.monotonic() + 90.0
    while True:
        try:
            exec_arn = sfn.start_execution(**kwargs)["executionArn"]
            break
        except ClientError as exc:
            # The role's freshly written KMS grant propagates to Step Functions with a lag.
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    # GetActivityTask long-polls up to ~60s server-side; retry until a token appears.
    client = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_activity_task(activityArn=activity_arn)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"activity task not scheduled within {timeout_s}s: {last!r}")


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_kms_key(ctx, description="sim2real-behav sfn test key"):
    kms = ctx.client("kms")
    resp = kms.create_key(Description=description, KeyUsage="ENCRYPT_DECRYPT")
    meta = resp["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _revoke_kms_crypto_access(ctx, key_id, *, timeout_s=90):
    """Overwrite the key policy to DENY all crypto ops to every principal (leaving
    management to account root for cleanup), then poll GenerateDataKey until the deny
    is actually enforced (KMS key-policy propagation isn't instantaneous)."""
    kms = ctx.client("kms")
    account = _account_id(ctx)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
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
        time.sleep(3)
    raise AssertionError("KMS deny-crypto key policy did not propagate in time")


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html
@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """SendTaskFailure fails KmsAccessDeniedException once the state machine's customer-managed key
    denies crypto, with the exact kms:Decrypt explicit-deny message naming the execution role and the
    key, rather than falling back to AWS-owned encryption or skipping encryption."""
    sfn = ctx.client("stepfunctions")
    key = _create_kms_key(ctx)
    key_arn = key["Arn"]

    act = _create_activity(ctx)
    definition = {
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": act["arn"], "TimeoutSeconds": 180, "End": True}},
    }
    arn = _create_state_machine(
        ctx,
        definition,
        encryption_configuration={
            "type": "CUSTOMER_MANAGED_KMS_KEY",
            "kmsKeyId": key_arn,
            "kmsDataKeyReusePeriodSeconds": 60,
        },
    )
    # The execution role's name appears in the KMS refusal below; read it while the key is usable.
    role_arn = sfn.describe_state_machine(stateMachineArn=arn)["roleArn"]
    role_name = role_arn.rsplit("/", 1)[1]
    exec_arn = _start_execution(ctx, arn, input_data={"probe": 1})
    task = _poll_activity_task(ctx, act["arn"])

    # Revoke only after the execution and task exist.
    _revoke_kms_crypto_access(ctx, key["KeyId"])

    # kmsDataKeyReusePeriodSeconds=60 lets Step Functions reuse a cached data key; wait out the
    # window so SendTaskFailure must request a fresh one against the denied key policy.
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        time.sleep(5)

    code, message = _error(
        lambda: sfn.send_task_failure(taskToken=task["taskToken"], error="BoomWithKms", cause="needs encryption")
    )
    assert code == "KmsAccessDeniedException", f"expected KmsAccessDeniedException, got {code}"
    # The message names the execution role's session, whose name Step Functions mints per call,
    # and ends with the KMS request id and SDK attempt count; everything else is graded exactly.
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/<session> is not authorized to "
        f"perform: kms:Decrypt on resource: {key_arn} with an explicit deny in a resource-based policy "
        "(Service: Kms, Status Code: 400, Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    stable = _SESSION.sub(r"\1<session> ", _stable(message) or "", count=1)
    assert stable == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
