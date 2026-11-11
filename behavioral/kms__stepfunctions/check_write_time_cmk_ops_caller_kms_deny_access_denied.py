"""write-time-cmk-ops-caller-kms-deny-access-denied."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "write-time-cmk-ops-caller-kms-deny-access-denied"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

_SESSION_NAME = "sim2real-xsvc-sfn-caller"
_DEFINITION = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})

# The relayed KMS message ends with the inner KMS call's request id and the SDK attempt count;
# those are the only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message):
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


def _caller_policy(deny_kms: bool) -> str:
    """states:* on every resource this check touches, plus an explicit Deny on kms:* unless
    deny_kms is False."""
    statements = [
        {
            "Sid": "AllowStates",
            "Effect": "Allow",
            "Action": [
                "states:CreateStateMachine",
                "states:CreateActivity",
                "states:UpdateStateMachine",
                "states:DeleteStateMachine",
                "states:DeleteActivity",
                "states:DescribeStateMachine",
                "states:DescribeActivity",
                "states:ListStateMachines",
                "states:ListActivities",
            ],
            "Resource": "*",
        },
        {"Sid": "AllowPassRole", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
    ]
    if deny_kms:
        statements.append({"Sid": "DenyKms", "Effect": "Deny", "Action": "kms:*", "Resource": "*"})
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _error_code(fn):
    """The Error.Code fn() raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _retry_until_kms_denied(attempt, undo_success, timeout_s=180.0, interval_s=5.0, streak=2):
    """Retry ``attempt()`` until it is refused KmsAccessDeniedException ``streak`` times in a
    row; return the last (code, message).

    Two things still propagate when this starts: the caller role's own states:* grant (seen as
    AccessDeniedException, always retried) and its freshly written kms:* Deny (seen as a
    lingering success). ``attempt`` must use a FRESH name/target on every call it actually
    creates or mutates, so a success before the Deny lands is a real effect, not an idempotent
    replay masking the next call's own check; ``undo_success`` reverts exactly that effect.
    """
    deadline = time.monotonic() + timeout_s
    denied_in_a_row = 0
    last = None
    while time.monotonic() < deadline:
        try:
            result = attempt()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if code == "AccessDeniedException" and "is not authorized to perform: states:" in (
                err.get("Message", "")
            ):
                time.sleep(interval_s)
                continue
            if code != "KmsAccessDeniedException":
                raise
            denied_in_a_row += 1
            last = (code, err.get("Message"))
            if denied_in_a_row >= streak:
                return last
        else:
            undo_success(result)
            denied_in_a_row = 0
        time.sleep(interval_s)
    raise AssertionError(
        f"never saw {streak} consecutive KmsAccessDeniedException attempts within {timeout_s}s; "
        f"last outcome: {last!r}"
    )


def _retry_until_succeeds(fn, timeout_s=240.0, interval_s=5.0):
    """Poll fn() until it returns normally, once the Deny has been lifted."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"still refused after {timeout_s}s: {last_exc}")


def _retry_invalid_principal(fn, timeout_s=90.0, interval_s=5.0):
    """A key policy naming a role created moments ago sees MalformedPolicyDocumentException
    ("invalid principals") until that role propagates to KMS's own validator."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") != "MalformedPolicyDocumentException" or "principal" not in (
                error.get("Message", "").lower()
            ):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"still invalid-principal after {timeout_s}s: {last_exc}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine, CreateActivity and UpdateStateMachine check a CMK with the CALLER's
    own credentials: a caller explicitly denied kms:* is refused KmsAccessDeniedException on
    all three, even though the key policy and the resource's own execution role both allow it.
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    account_id = ctx.account
    root_arn = f"arn:aws:iam::{account_id}:root"

    caller_role_name = ctx.unique_name("sim2real-xsvc-sfn-caller-")
    caller_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": account_id}, "Action": "sts:AssumeRole"}],
    })
    caller_role_arn = iam.create_role(
        RoleName=caller_role_name, AssumeRolePolicyDocument=caller_trust,
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=caller_role_name))
    iam.put_role_policy(
        RoleName=caller_role_name, PolicyName="caller", PolicyDocument=_caller_policy(deny_kms=True),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=caller_role_name, PolicyName="caller"))

    # The key policy grants the caller role unconditional KMS access, so the only thing that can
    # block it below is its own identity-side Deny.
    key = _retry_invalid_principal(lambda: kms.create_key(
        Description=ctx.unique_name("sim2real-xsvc-sfn-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "Admin", "Effect": "Allow", "Principal": {"AWS": root_arn},
                 "Action": "kms:*", "Resource": "*"},
                {"Sid": "AllowCaller", "Effect": "Allow", "Principal": {"AWS": caller_role_arn},
                 "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"], "Resource": "*"},
            ],
        }),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    ))["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    sm_role_name = ctx.unique_name("sim2real-xsvc-sfn-role-")
    sm_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    sm_role_arn = iam.create_role(
        RoleName=sm_role_name, AssumeRolePolicyDocument=sm_trust,
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=sm_role_name))
    iam.put_role_policy(
        RoleName=sm_role_name, PolicyName="kms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": key_arn},
        ]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=sm_role_name, PolicyName="kms"))

    creds = _assume_caller(sts, caller_role_arn)
    restricted_sfn = ctx.client("stepfunctions", creds=creds)

    caller_arn = f"arn:aws:sts::{account_id}:assumed-role/{caller_role_name}/{_SESSION_NAME}"
    expected_denial = (
        f"User: {caller_arn} is not authorized to perform: kms:DescribeKey on resource: "
        f"{key_arn} with an explicit deny in an identity-based policy (Service: Kms, Status "
        "Code: 400, Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    encryption = {
        "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_id, "kmsDataKeyReusePeriodSeconds": 300,
    }

    sm_attempts: list[str] = []

    def attempt_create_sm():
        name = ctx.unique_name("sim2real-xsvc-sfn-sm-")
        sm_attempts.append(name)
        return restricted_sfn.create_state_machine(
            name=name, definition=_DEFINITION, roleArn=sm_role_arn, encryptionConfiguration=encryption,
        )

    def undo_sm(result):
        sfn.delete_state_machine(stateMachineArn=result["stateMachineArn"])

    code, message = _retry_until_kms_denied(attempt_create_sm, undo_sm)
    assert code == "KmsAccessDeniedException", f"expected KmsAccessDeniedException, got {code!r}"
    assert _stable(message) == expected_denial, f"expected message {expected_denial!r}, got {message!r}"
    listed = sfn.list_state_machines()["stateMachines"]
    assert sm_attempts[-1] not in {m["name"] for m in listed}, (
        f"a CreateStateMachine refused KmsAccessDeniedException must create no state machine, "
        f"but {sm_attempts[-1]!r} is listed"
    )

    act_attempts: list[str] = []

    def attempt_create_activity():
        name = ctx.unique_name("sim2real-xsvc-sfn-act-")
        act_attempts.append(name)
        return restricted_sfn.create_activity(name=name, encryptionConfiguration=encryption)

    def undo_activity(result):
        sfn.delete_activity(activityArn=result["activityArn"])

    code, message = _retry_until_kms_denied(attempt_create_activity, undo_activity)
    assert code == "KmsAccessDeniedException", f"expected KmsAccessDeniedException, got {code!r}"
    assert _stable(message) == expected_denial, f"expected message {expected_denial!r}, got {message!r}"
    activities = _activities_named(sfn, act_attempts[-1])
    assert activities == [], (
        f"a CreateActivity refused KmsAccessDeniedException must create no activity, got {activities}"
    )

    # UpdateStateMachine: start from a plain (default-encrypted) machine the caller role can
    # create without touching KMS, then try to turn its encryption to the CMK.
    plain_arn = restricted_sfn.create_state_machine(
        name=ctx.unique_name("sim2real-xsvc-sfn-sm-plain-"), definition=_DEFINITION, roleArn=sm_role_arn,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=plain_arn))
    before_enc = sfn.describe_state_machine(stateMachineArn=plain_arn).get("encryptionConfiguration")

    def attempt_update_sm():
        return restricted_sfn.update_state_machine(
            stateMachineArn=plain_arn, definition=_DEFINITION, encryptionConfiguration=encryption,
        )

    def undo_update_sm(_result):
        # Succeeded before the Deny landed: revert to the baseline encryption so the next
        # attempt, and the "unchanged" assertion below, both start from the same state.
        restricted_sfn.update_state_machine(
            stateMachineArn=plain_arn, definition=_DEFINITION,
            encryptionConfiguration={"type": "AWS_OWNED_KEY"},
        )

    code, message = _retry_until_kms_denied(attempt_update_sm, undo_update_sm)
    assert code == "KmsAccessDeniedException", f"expected KmsAccessDeniedException, got {code!r}"
    assert _stable(message) == expected_denial, f"expected message {expected_denial!r}, got {message!r}"
    after_enc = sfn.describe_state_machine(stateMachineArn=plain_arn).get("encryptionConfiguration")
    assert after_enc == before_enc, (
        f"a refused UpdateStateMachine must not change the encryptionConfiguration: "
        f"before={before_enc!r} after={after_enc!r}"
    )

    # Positive control: lift the Deny, the identical calls now succeed.
    iam.put_role_policy(
        RoleName=caller_role_name, PolicyName="caller", PolicyDocument=_caller_policy(deny_kms=False),
    )
    sm_arn = _retry_until_succeeds(attempt_create_sm)["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
    enc_now = sfn.describe_state_machine(stateMachineArn=sm_arn).get("encryptionConfiguration")
    assert enc_now.get("type") == "CUSTOMER_MANAGED_KMS_KEY" and enc_now.get("kmsKeyId") == key_arn, (
        f"once the Deny is lifted CreateStateMachine must succeed with the CMK applied, got {enc_now!r}"
    )

    act_arn = _retry_until_succeeds(attempt_create_activity)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=act_arn))
    act_enc = sfn.describe_activity(activityArn=act_arn).get("encryptionConfiguration")
    assert act_enc.get("type") == "CUSTOMER_MANAGED_KMS_KEY" and act_enc.get("kmsKeyId") == key_arn, (
        f"once the Deny is lifted CreateActivity must succeed with the CMK applied, got {act_enc!r}"
    )

    _retry_until_succeeds(attempt_update_sm)
    enc_updated = sfn.describe_state_machine(stateMachineArn=plain_arn).get("encryptionConfiguration")
    assert enc_updated.get("type") == "CUSTOMER_MANAGED_KMS_KEY" and enc_updated.get("kmsKeyId") == key_arn, (
        f"once the Deny is lifted UpdateStateMachine must succeed with the CMK applied, got {enc_updated!r}"
    )


def _activities_named(sfn, name):
    pages = sfn.get_paginator("list_activities").paginate()
    return [a for page in pages for a in page["activities"] if a["name"] == name]


def _assume_caller(sts, role_arn, attempts=8, interval_s=3.0):
    last_exc = None
    for _ in range(attempts):
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            return {
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            }
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn!r} after retries: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
