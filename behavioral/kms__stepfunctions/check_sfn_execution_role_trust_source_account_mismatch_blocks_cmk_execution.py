"""sfn-execution-role-trust-source-account-mismatch-blocks-cmk-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-execution-role-trust-source-account-mismatch-blocks-cmk-execution"
GROUP = "permission-boundary"
SERVICES = ["kms", "stepfunctions"]

_DEFINITION = json.dumps({"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}})


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A trust naming another account's aws:SourceAccount can never be assumed: StartExecution
    on a CMK-encrypted STANDARD machine raises KmsAccessDeniedException naming the denial, while
    a same-account twin SUCCEEDS."""
    key_arn = _cmk(ctx)
    foreign_account = "111122223333"

    bad_role_arn = _trusted_role(ctx, source_account=foreign_account, kms_key_arn=key_arn)
    ok_role_arn = _trusted_role(ctx, source_account=ctx.account, kms_key_arn=key_arn)

    bad_arn = _create_state_machine(ctx, bad_role_arn, key_arn)
    expected_message = (
        "com.amazonaws.sfn.invoker.sts.AssumeRoleFailedCacheableException: The principal "
        f"states.amazonaws.com is not authorized to assume the provided role. (role: {bad_role_arn})"
    )
    code, message = _start_until_permanent_failure(ctx, bad_arn, expected_message)
    assert code == "KmsAccessDeniedException", (
        f"a SourceAccount-mismatched trust must fail StartExecution with KmsAccessDeniedException; "
        f"got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    ok_arn = _create_state_machine(ctx, ok_role_arn, key_arn)
    ok_exec = _start_execution_retrying_kms(ctx, ok_arn)
    ok_final = _wait_terminal(ctx, ok_exec)
    assert ok_final["status"] == "SUCCEEDED", (
        f"the same-account twin must SUCCEED; got {ok_final['status']!r} "
        f"cause={ok_final.get('cause')!r}"
    )


def _cmk(ctx) -> str:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description="sim2real behavioral: sfn execution role SourceAccount mismatch",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta["Arn"]


def _trusted_role(ctx, *, source_account: str, kms_key_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-acctrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": source_account},
                    "ArnLike": {"aws:SourceArn":
                                f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:*"},
                },
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="kms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
             "Resource": kms_key_arn},
        ]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="kms"))
    return role_arn


def _create_state_machine(ctx, role_arn: str, key_arn: str, timeout_s: float = 150.0) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn-acctsm-")
    deadline = time.monotonic() + timeout_s
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="STANDARD",
                encryptionConfiguration={
                    "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
                    "kmsDataKeyReusePeriodSeconds": 60,
                },
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3.0)
    else:
        raise AssertionError(f"CreateStateMachine still AccessDenied after {timeout_s}s: {last}")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution_retrying_kms(ctx, sm_arn: str, timeout_s: float = 150.0) -> str:
    """StartExecution, retrying only KmsAccessDeniedException while the role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException":
                raise
            last = exc
            time.sleep(4.0)
    raise AssertionError(f"StartExecution still KmsAccessDenied after {timeout_s}s: {last}")


def _start_until_permanent_failure(ctx, sm_arn: str, expected_message: str, timeout_s: float = 150.0):
    """StartExecution, retrying a KMS error only until it stops differing from the SourceAccount
    mismatch's permanent denial (which, unlike a propagation race, never clears)."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            sfn.start_execution(stateMachineArn=sm_arn, input="{}")
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "KmsAccessDeniedException" and err.get("Message") == expected_message:
                return err["Code"], err.get("Message")
            if err["Code"] != "KmsAccessDeniedException":
                raise
            last = err
            time.sleep(4.0)
            continue
        raise AssertionError("StartExecution unexpectedly succeeded against the mismatched trust")
    raise AssertionError(f"StartExecution never reached the expected permanent denial: {last!r}")


def _wait_terminal(ctx, exec_arn: str, timeout_s: float = 120.0, poll_s: float = 2.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(poll_s)
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
