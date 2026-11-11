"""describe-execution-kms-access-denied."""
from __future__ import annotations

import json
import re
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-execution-kms-access-denied"
GROUP = 'execution_lifecycle'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns, so the
    outcome never rests on an execution role the account happens to carry."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD",
                          encryption_configuration=None):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    kwargs = {
        "name": name,
        "definition": json.dumps(definition),
        "roleArn": role_arn,
        "type": sm_type,
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    if encryption_configuration is not None:
        kwargs["encryptionConfiguration"] = encryption_configuration
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(**kwargs)["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_status(ctx, exec_arn, statuses, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in statuses:
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not in {statuses} within {timeout_s}s: {last!r}")


def _asl_wait(seconds):
    return {
        "Comment": "behavioral-wait",
        "StartAt": "W",
        "States": {"W": {"Type": "Wait", "Seconds": seconds, "End": True}},
    }


def _error_or_result(fn):
    """Call fn(); return its ClientError as a (code, HTTP status, stable message) tuple, or the
    successful response dict itself, which no tuple can equal, so a caller can poll for either the
    error or the payload in one shot."""
    try:
        return fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                _stable(exc.response.get("Error", {}).get("Message")))


# The relayed KMS message ends with the inner KMS call's request id and the SDK attempt count;
# those are the only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message):
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_kms_key(ctx):
    """Create a symmetric customer-managed KMS key and schedule it for deletion at cleanup."""
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description="sim2real-behav sfn test key",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    meta = resp["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _grant_kms_crypto_access(ctx, key_id, role_arn):
    """Set the key policy to explicitly ALLOW the state-machine execution role to negotiate data
    keys, alongside root management access. Step Functions assumes this role to call KMS on the
    check's behalf, so without this explicit grant StartExecution itself is denied before the
    scenario under test (a read denied after the grant is revoked) can even be set up."""
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
                "Action": [
                    "kms:GenerateDataKey",
                    "kms:Decrypt",
                    "kms:DescribeKey",
                ],
                "Resource": "*",
            },
        ],
    }
    # KMS rejects a key policy naming a principal IAM has not propagated yet; the role is fresh.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))
            return
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "MalformedPolicyDocumentException"
                    or time.monotonic() > deadline):
                raise
            time.sleep(3)


def _revoke_kms_crypto_access(ctx, key_id, *, timeout_s=90):
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

    def probe():
        try:
            kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
            return False
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code") == "AccessDeniedException"

    _poll_until(
        probe,
        lambda denied: denied,
        timeout_s=timeout_s,
        interval_s=3,
        description="KMS crypto-operation deny is enforced",
    )


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeExecution on a CMK-encrypted state machine's open execution raises
    KmsAccessDeniedException once the key's crypto access is revoked, and succeeds again once it is
    restored, so the read never falls back to unencrypted or cached data.
    """
    sfn = ctx.client("stepfunctions")
    key = _create_kms_key(ctx)
    key_arn = key["Arn"]
    role_arn = _create_sfn_role(ctx)
    reuse_period = 60

    # StartExecution on a CUSTOMER_MANAGED_KMS_KEY machine needs the execution role to hold
    # kms:GenerateDataKey/Decrypt on the key, so the key policy grants it.
    _grant_kms_crypto_access(ctx, key["KeyId"], role_arn)

    arn = _create_state_machine(
        ctx,
        _asl_wait(900),
        role_arn,
        encryption_configuration={
            "type": "CUSTOMER_MANAGED_KMS_KEY",
            "kmsKeyId": key_arn,
            "kmsDataKeyReusePeriodSeconds": reuse_period,
        },
    )
    exec_arn = _start_execution(ctx, arn, input_data={"probe": 1})
    _wait_execution_status(ctx, exec_arn, {"RUNNING"}, timeout_s=20)
    # The execution role decrypts the input as the Wait state is entered; revoking before that
    # fails the execution itself. Hold the open window from inside the Wait state.
    _poll_until(
        lambda: [e["type"] for e in sfn.get_execution_history(
            executionArn=exec_arn, maxResults=20)["events"]],
        lambda types: "WaitStateEntered" in types,
        timeout_s=30,
        interval_s=1,
        description="the execution has entered its Wait state",
    )

    # Positive control: reads succeed normally while the key is still accessible.
    before = sfn.describe_execution(executionArn=exec_arn)
    assert before["status"] == "RUNNING", f"expected RUNNING before revoking KMS access, got {before}"

    _revoke_kms_crypto_access(ctx, key["KeyId"])

    # kmsDataKeyReusePeriodSeconds lets Step Functions reuse a data key it negotiated before the
    # revoke, so a read made right after it may still succeed. Poll, bounded by the reuse window
    # plus margin, until the read is refused; the execution stays open throughout.
    refused = _poll_until(
        lambda: _error_or_result(lambda: sfn.describe_execution(executionArn=exec_arn)),
        lambda r: isinstance(r, tuple),
        timeout_s=reuse_period + 60,
        interval_s=3,
        description="DescribeExecution is refused once the key denies crypto operations",
    )
    # The refusal relays KMS's own message; only its request id and attempt count vary.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        "KmsAccessDeniedException",
        400,
        f"User: {caller_arn} is not authorized to perform: kms:Decrypt on resource: {key_arn} "
        "with an explicit deny in a resource-based policy (Service: Kms, Status Code: 400, "
        "Request ID: <request-id>) (SDK Attempt Count: <n>)",
    )
    assert refused == expected, f"expected {expected!r}, got {refused!r}"

    # Restore leg: grant access back and demand the identical DescribeExecution call succeeds
    # again, proving the earlier failure tracked the key policy rather than some other break (an
    # expired execution, a torn-down state machine, a permanently wedged client).
    _grant_kms_crypto_access(ctx, key["KeyId"], role_arn)
    after = _poll_until(
        lambda: _error_or_result(lambda: sfn.describe_execution(executionArn=exec_arn)),
        lambda result: isinstance(result, dict),
        timeout_s=180,
        interval_s=3,
        description="DescribeExecution succeeds again after KMS access is restored",
    )
    assert after["status"] == "RUNNING", f"expected RUNNING after restoring KMS access, got {after}"

    # Best-effort: end the dangling execution (no error/cause payload needing encryption).
    try:
        sfn.stop_execution(executionArn=exec_arn)
    except Exception:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
