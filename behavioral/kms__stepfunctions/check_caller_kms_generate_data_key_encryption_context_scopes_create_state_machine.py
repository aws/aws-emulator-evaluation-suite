"""caller-kms-generate-data-key-encryption-context-scopes-create-state-machine."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "caller-kms-generate-data-key-encryption-context-scopes-create-state-machine"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

_DEFINITION = json.dumps({"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}})

_STATES_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# The KMS denial ends with the request id and the SDK attempt count; those are the only parts
# that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message: str | None) -> str | None:
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _error_code(fn) -> str:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError("expected the call to be refused, but it succeeded")


def _assume_role_with_retry(sts, role_arn: str, session_name: str, attempts: int = 15,
                             delay_s: float = 4.0) -> dict:
    """Retry AssumeRole while a just-created role's trust propagates."""
    last_exc = None
    for _ in range(attempts):
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _retry_propagation(fn, codes: set[str], attempts: int = 30, delay_s: float = 5.0):
    """Retry ``fn`` while it raises one of ``codes`` -- absorbs identity-policy and freshly
    issued credential propagation lag on a call expected to SUCCEED; never on one expected
    to fail."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes:
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _expected_denial(assumed_arn: str, key_arn: str) -> str:
    """KMS's exact GenerateDataKey denial text, request id and attempt count masked."""
    return (
        f"User: {assumed_arn} is not authorized to perform: kms:GenerateDataKey on resource: "
        f"{key_arn} because no identity-based policy allows the kms:GenerateDataKey action "
        "(Service: Kms, Status Code: 400, Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )


def _key(ctx) -> str:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-behav {CHECK[:200]}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(_teardown(
        lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7)))
    return meta["Arn"]


def _exec_role(ctx) -> str:
    """A states.amazonaws.com-assumable execution role; the Pass-only machine calls nothing."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnexec-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_STATES_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _caller_role(ctx, key_arn: str, exec_role_arn: str, region: str, account: str) -> tuple[str, str]:
    """A role this check assumes to call CreateStateMachine, whose only KMS grant is
    kms:GenerateDataKey conditioned on the EncryptionContext Step Functions sends for the
    state machine's own ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnctxcaller-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                       "Action": "sts:AssumeRole"}],
    })
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))

    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow",
             "Action": ["states:CreateStateMachine", "states:DescribeStateMachine",
                        "states:TagResource"],
             "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": exec_role_arn},
            {"Effect": "Allow", "Action": "kms:DescribeKey", "Resource": key_arn},
            {"Effect": "Allow", "Action": "kms:GenerateDataKey", "Resource": key_arn,
             "Condition": {"StringLike": {
                 "kms:EncryptionContext:aws:states:stateMachineArn":
                     f"arn:aws:states:{region}:{account}:stateMachine:valid*"}}},
        ],
    })
    iam.put_role_policy(RoleName=name, PolicyName="scoped-generate-data-key", PolicyDocument=policy)
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="scoped-generate-data-key"),
        "NoSuchEntity"))
    return name, arn


@tags("axis:rejection", "cap:c7", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine calls kms:GenerateDataKey as the caller, not the execution role: a
    caller policy conditioned on kms:EncryptionContext:aws:states:stateMachineArn lets a matching
    name create and refuses a non-matching one with the exact KmsAccessDeniedException.
    """
    sfn = ctx.client("stepfunctions")
    sts = ctx.client("sts")
    account, region = ctx.account, ctx.region

    key_arn = _key(ctx)
    exec_role_arn = _exec_role(ctx)
    caller_role_name, caller_role_arn = _caller_role(ctx, key_arn, exec_role_arn, region, account)

    session_name = ctx.unique_name("sim2real-session-")
    creds = _assume_role_with_retry(sts, caller_role_arn, session_name)
    caller_sfn = ctx.client("stepfunctions", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    assumed_arn = f"arn:aws:sts::{account}:assumed-role/{caller_role_name}/{session_name}"

    good_name = ctx.unique_name("valid-sim2real-behav-sfnctx-")
    bad_name = ctx.unique_name("sim2real-behav-sfnctx-nomatch-")

    def _create(name: str):
        return caller_sfn.create_state_machine(
            name=name, definition=_DEFINITION, roleArn=exec_role_arn, type="STANDARD",
            encryptionConfiguration={"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
                                      "kmsDataKeyReusePeriodSeconds": 60},
            tags=[{"key": "sim2real", "value": CHECK[:250]}],
        )["stateMachineArn"]

    # Positive control: a name matching the condition's pattern must create, once the caller
    # role's own policy (states:CreateStateMachine, iam:PassRole, kms:GenerateDataKey) has
    # propagated -- the only reason this retries AccessDenied/KmsAccessDenied here.
    good_arn = _retry_propagation(
        lambda: _create(good_name),
        {"AccessDeniedException", "KmsAccessDeniedException", "UnrecognizedClientException"})
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=good_arn),
                              "StateMachineDoesNotExist"))
    desc = sfn.describe_state_machine(stateMachineArn=good_arn)
    assert desc["stateMachineArn"] == good_arn, (
        f"a state machine name matching the caller's EncryptionContext condition must create; "
        f"describe returned {desc!r}")

    code, message = _error(lambda: _create(bad_name))
    assert code == "KmsAccessDeniedException", (
        f"CreateStateMachine for a name outside the condition's pattern must be refused with "
        f"KmsAccessDeniedException; got {code!r}: {message!r}")
    expected = _expected_denial(assumed_arn, key_arn)
    assert _stable(message) == expected, f"expected the exact KMS denial {expected!r}; got {message!r}"

    bad_arn = f"arn:aws:states:{region}:{account}:stateMachine:{bad_name}"
    code2 = _error_code(lambda: sfn.describe_state_machine(stateMachineArn=bad_arn))
    assert code2 == "StateMachineDoesNotExist", (
        f"a refused CreateStateMachine must create nothing; describing the would-be ARN gave "
        f"{code2!r}, expected StateMachineDoesNotExist")

    # Control: the identical bad_name, same key and definition, under unrestricted credentials,
    # creates fine -- so the refusal is the caller role's EncryptionContext condition, not a
    # malformed key or a name the service itself rejects.
    control_arn = sfn.create_state_machine(
        name=bad_name, definition=_DEFINITION, roleArn=exec_role_arn, type="STANDARD",
        encryptionConfiguration={"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
                                  "kmsDataKeyReusePeriodSeconds": 60},
        tags=[{"key": "sim2real", "value": CHECK[:250]}],
    )["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=control_arn),
                              "StateMachineDoesNotExist"))
    assert control_arn == bad_arn, (
        f"the control create must land on the same ARN the restricted caller was refused; "
        f"got {control_arn!r}, expected {bad_arn!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
