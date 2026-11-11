"""create-state-machine-kms-via-service-condition."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-kms-via-service-condition"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

_SESSION_NAME = "sim2real-xsvc-sfn-viasvc-caller"
_DEFINITION = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})
_CALLER_CRYPTO_ACTIONS = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]

# The relayed KMS message ends with the inner KMS call's request id and the SDK attempt count;
# those are the only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message):
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


def _caller_statement(caller_role_arn: str, via_service: str, string_not_like: bool) -> dict:
    """The caller's grant, gated on kms:ViaService either matching (string_not_like False) or
    NOT matching (string_not_like True) the Step Functions service endpoint."""
    operator = "StringNotLike" if string_not_like else "StringEquals"
    return {
        "Sid": "AllowCallerViaService",
        "Effect": "Allow",
        "Principal": {"AWS": caller_role_arn},
        "Action": _CALLER_CRYPTO_ACTIONS,
        "Resource": "*",
        "Condition": {operator: {"kms:ViaService": via_service}},
    }


def _key_policy(root_arn: str, caller_role_arn: str, exec_role_arn: str, via_service: str,
                string_not_like: bool) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Admin", "Effect": "Allow", "Principal": {"AWS": root_arn},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "AllowExecRole", "Effect": "Allow", "Principal": {"AWS": exec_role_arn},
             "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*"},
            _caller_statement(caller_role_arn, via_service, string_not_like),
        ],
    })


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


def _retry_propagating(fn, timeout_s=180.0, interval_s=5.0):
    """Retry while either the caller role's states:* grant or the key policy's ViaService grant
    is still propagating; any other failure (including a steady-state KmsAccessDeniedException)
    propagates once the budget is spent."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if code not in ("AccessDeniedException", "KmsAccessDeniedException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _retry_until_kms_denied(make_name, create, delete, timeout_s=180.0, interval_s=5.0, streak=2):
    """Retry a CreateStateMachine with a FRESH name each attempt until it is refused
    KmsAccessDeniedException ``streak`` times in a row; return the last (code, message).

    A freshly written key-policy condition takes time to propagate, so an early attempt can
    still succeed — reusing one name across attempts would then make a later attempt an
    idempotent replay of an already-created machine rather than a fresh check, so each attempt
    gets its own name, and an accidental success is torn down before the next attempt.
    """
    deadline = time.monotonic() + timeout_s
    denied_in_a_row = 0
    last = None
    while time.monotonic() < deadline:
        name = make_name()
        try:
            result = create(name)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "KmsAccessDeniedException":
                raise
            denied_in_a_row += 1
            last = (err.get("Code"), err.get("Message"))
            if denied_in_a_row >= streak:
                return last
        else:
            delete(result)
            denied_in_a_row = 0
        time.sleep(interval_s)
    raise AssertionError(
        f"never saw {streak} consecutive KmsAccessDeniedException attempts within {timeout_s}s; "
        f"last outcome: {last!r}"
    )


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


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CreateStateMachine CMK check honors kms:ViaService on the caller's key-policy grant:
    a grant that matches "states.<region>.amazonaws.com" is enough to create, and flipping the
    same condition to exclude that service denies the identical create KmsAccessDeniedException.
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    account_id = ctx.account
    root_arn = f"arn:aws:iam::{account_id}:root"
    via_service = f"states.{ctx.region}.amazonaws.com"

    caller_role_name = ctx.unique_name("sim2real-xsvc-sfn-viasvc-caller-")
    caller_role_arn = iam.create_role(
        RoleName=caller_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": account_id},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=caller_role_name))
    # No kms:* in the caller's identity policy at all: every grant it has comes from the key's
    # own resource policy below.
    iam.put_role_policy(
        RoleName=caller_role_name, PolicyName="caller",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "AllowStates", "Effect": "Allow", "Action": [
                    "states:CreateStateMachine", "states:DeleteStateMachine",
                    "states:DescribeStateMachine", "states:ListStateMachines",
                ], "Resource": "*"},
                {"Sid": "AllowPassRole", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=caller_role_name, PolicyName="caller"))

    sm_role_name = ctx.unique_name("sim2real-xsvc-sfn-viasvc-role-")
    sm_role_arn = iam.create_role(
        RoleName=sm_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=sm_role_name))

    key = _retry_invalid_principal(lambda: kms.create_key(
        Description=ctx.unique_name("sim2real-xsvc-sfn-viasvc-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
        Policy=_key_policy(root_arn, caller_role_arn, sm_role_arn, via_service, string_not_like=False),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    ))["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    live = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    conditions = [s.get("Condition") for s in live["Statement"] if s.get("Sid") == "AllowCallerViaService"]
    assert conditions == [{"StringEquals": {"kms:ViaService": via_service}}], (
        f"the ViaService condition was not persisted on the key policy ({conditions!r}), so the "
        "rest of this check would grade nothing"
    )

    creds = _assume_caller(sts, caller_role_arn)
    restricted_sfn = ctx.client("stepfunctions", creds=creds)
    encryption = {
        "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_id, "kmsDataKeyReusePeriodSeconds": 300,
    }

    allowed_name = ctx.unique_name("sim2real-xsvc-sfn-viasvc-allowed-")
    allowed_arn = _retry_propagating(lambda: restricted_sfn.create_state_machine(
        name=allowed_name, definition=_DEFINITION, roleArn=sm_role_arn, encryptionConfiguration=encryption,
    ))["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=allowed_arn))
    allowed_enc = sfn.describe_state_machine(stateMachineArn=allowed_arn).get("encryptionConfiguration")
    assert allowed_enc.get("type") == "CUSTOMER_MANAGED_KMS_KEY" and allowed_enc.get("kmsKeyId") == key_arn, (
        f"a kms:ViaService=={via_service!r} grant must be enough for the caller's own "
        f"CreateStateMachine to apply the CMK; got {allowed_enc!r}"
    )

    # Flip the SAME condition to exclude the Step Functions service path.
    kms.put_key_policy(
        KeyId=key_id, PolicyName="default",
        Policy=_key_policy(root_arn, caller_role_arn, sm_role_arn, via_service, string_not_like=True),
    )

    denied_attempts: list[str] = []

    def make_denied_name():
        name = ctx.unique_name("sim2real-xsvc-sfn-viasvc-denied-")
        denied_attempts.append(name)
        return name

    def create_denied(name):
        return restricted_sfn.create_state_machine(
            name=name, definition=_DEFINITION, roleArn=sm_role_arn, encryptionConfiguration=encryption,
        )

    def delete_denied(result):
        sfn.delete_state_machine(stateMachineArn=result["stateMachineArn"])

    code, message = _retry_until_kms_denied(make_denied_name, create_denied, delete_denied)
    assert code == "KmsAccessDeniedException", f"expected KmsAccessDeniedException, got {code!r}"
    caller_arn = f"arn:aws:sts::{account_id}:assumed-role/{caller_role_name}/{_SESSION_NAME}"
    expected_denial = (
        f"User: {caller_arn} is not authorized to perform: kms:DescribeKey on resource: "
        f"{key_arn} because no identity-based policy allows the kms:DescribeKey action "
        "(Service: Kms, Status Code: 400, Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    assert _stable(message) == expected_denial, f"expected message {expected_denial!r}, got {message!r}"

    last_denied_name = denied_attempts[-1]
    listed = sfn.list_state_machines()["stateMachines"]
    assert last_denied_name not in {m["name"] for m in listed}, (
        f"a CreateStateMachine refused KmsAccessDeniedException must create no state machine, "
        f"but {last_denied_name!r} is listed"
    )

    # The earlier, allowed machine is untouched by the policy flip: proof the denial above is
    # about the new create's authorization, not about the key becoming unusable outright.
    still_enc = sfn.describe_state_machine(stateMachineArn=allowed_arn).get("encryptionConfiguration")
    assert still_enc == allowed_enc, (
        f"the earlier successfully-created machine's encryption must be unaffected by the "
        f"policy flip: before={allowed_enc!r} after={still_enc!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
