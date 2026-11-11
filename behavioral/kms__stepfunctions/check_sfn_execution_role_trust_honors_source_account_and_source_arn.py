"""sfn-execution-role-trust-honors-source-account-and-source-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-execution-role-trust-honors-source-account-and-source-arn"
GROUP = "permission-boundary"
SERVICES = ["kms", "stepfunctions"]

_DEFINITION = json.dumps({"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}})


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An execution role trusting states.amazonaws.com on aws:SourceAccount and aws:SourceArn is
    assumed: a CMK-encrypted, non-ASCII-named STANDARD execution and a plain EXPRESS sync
    execution both SUCCEED, while a twin whose aws:SourceArn matches no machine is refused."""
    sfn = ctx.client("stepfunctions")
    key_arn = _cmk(ctx)

    # STANDARD: trust scoped to a wildcard SourceArn over every state machine in the account.
    wildcard_role_arn = _trusted_role(
        ctx, source_arn_pattern=f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:*",
        kms_key_arn=key_arn,
    )
    std_name = ctx.unique_name("sim2real-behav-sfn-trust-さくら-")
    std_arn = _create_state_machine(
        ctx, std_name, wildcard_role_arn, "STANDARD", encryption_key_arn=key_arn,
    )
    desc = sfn.describe_state_machine(stateMachineArn=std_arn)
    assert desc["encryptionConfiguration"]["kmsKeyId"] == key_arn, (
        f"expected the CMK configured at creation, got {desc.get('encryptionConfiguration')!r}"
    )
    std_exec = _start_execution_retrying_kms(sfn, std_arn)
    std_final = _wait_terminal(sfn, std_exec)
    assert std_final["status"] == "SUCCEEDED", (
        f"a CMK-encrypted STANDARD execution under an honored SourceAccount/SourceArn trust "
        f"must SUCCEED; got {std_final['status']!r} cause={std_final.get('cause')!r}"
    )

    # EXPRESS: trust scoped to the exact SM ARN this execution targets, computed before the
    # state machine exists (both it and the SM name derive deterministically from ctx).
    express_name = ctx.unique_name("sim2real-behav-sfn-trust-express-")
    express_arn = (
        f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{express_name}"
    )
    exact_role_arn = _trusted_role(ctx, source_arn_pattern=express_arn, kms_key_arn=None)
    created_arn = _create_state_machine(ctx, express_name, exact_role_arn, "EXPRESS")
    assert created_arn == express_arn, (
        f"the SM ARN computed ahead of creation must match the one CreateStateMachine returns; "
        f"expected {express_arn!r}, got {created_arn!r}"
    )
    sync = _start_sync_execution_retrying(sfn, created_arn)
    assert sync["status"] == "SUCCEEDED", (
        f"an EXPRESS sync execution under a trust scoped to the exact SM ARN must SUCCEED; "
        f"got {sync['status']!r} error={sync.get('error')!r} cause={sync.get('cause')!r}"
    )

    # Negative twin: the same account, key and definition, but the trust's aws:SourceArn names a
    # state machine that is not the one starting, so Step Functions can never assume the role.
    mismatch_role_arn = _trusted_role(
        ctx,
        source_arn_pattern=f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:no-such-machine",
        kms_key_arn=key_arn,
    )
    mismatch_arn = _create_state_machine(
        ctx, ctx.unique_name("sim2real-behav-sfn-trust-nomatch-"), mismatch_role_arn, "STANDARD",
        encryption_key_arn=key_arn,
    )
    expected_message = (
        "com.amazonaws.sfn.invoker.sts.AssumeRoleFailedCacheableException: The principal "
        "states.amazonaws.com is not authorized to assume the provided role. "
        f"(role: {mismatch_role_arn})"
    )
    code, message = _start_until_permanent_failure(sfn, mismatch_arn, expected_message)
    assert code == "KmsAccessDeniedException", (
        f"a trust whose aws:SourceArn does not match the starting machine must fail StartExecution "
        f"with KmsAccessDeniedException; got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _cmk(ctx) -> str:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description="sim2real behavioral: sfn execution role trust condition",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta["Arn"]


def _trust_policy(ctx, source_arn_pattern: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {"aws:SourceAccount": ctx.account},
                "ArnLike": {"aws:SourceArn": source_arn_pattern},
            },
        }],
    })


def _trusted_role(ctx, *, source_arn_pattern: str, kms_key_arn: str | None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-trustrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_trust_policy(ctx, source_arn_pattern),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if kms_key_arn:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="kms",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
                 "Resource": kms_key_arn},
            ]}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="kms"))
    return role_arn


def _create_state_machine(
    ctx, name: str, role_arn: str, sm_type: str, *, encryption_key_arn: str | None = None,
    timeout_s: float = 150.0,
) -> str:
    """CreateStateMachine, retrying while the fresh role's trust has not yet propagated in IAM."""
    sfn = ctx.client("stepfunctions")
    kwargs: dict = dict(
        name=name, definition=_DEFINITION, roleArn=role_arn, type=sm_type,
        tags=[{"key": "sim2real", "value": CHECK[:250]}],
    )
    if encryption_key_arn:
        kwargs["encryptionConfiguration"] = {
            "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": encryption_key_arn,
            "kmsDataKeyReusePeriodSeconds": 60,
        }
    deadline = time.monotonic() + timeout_s
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(**kwargs)["stateMachineArn"]
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


def _start_execution_retrying_kms(sfn, sm_arn: str, timeout_s: float = 150.0) -> str:
    """StartExecution, retrying only KmsAccessDeniedException while the role's trust propagates."""
    deadline = time.monotonic() + timeout_s
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException":
                raise
            last = exc
            time.sleep(4.0)
    raise AssertionError(f"StartExecution still KmsAccessDenied after {timeout_s}s: {last}")


def _start_until_permanent_failure(sfn, sm_arn: str, expected_message: str,
                                   timeout_s: float = 150.0) -> tuple[str, str | None]:
    """StartExecution, retrying a KMS error only until it reads as the trust mismatch's permanent
    denial, which, unlike a propagation race, never clears."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "KmsAccessDeniedException":
                raise
            if err.get("Message") == expected_message:
                return err["Code"], err.get("Message")
            last = err
            time.sleep(4.0)
            continue
        raise AssertionError(f"StartExecution unexpectedly started {arn!r} against the mismatched trust")
    raise AssertionError(f"StartExecution never reached the expected permanent denial: {last!r}")


def _start_sync_execution_retrying(sfn, sm_arn: str, timeout_s: float = 150.0) -> dict:
    """StartSyncExecution, retrying only while the fresh trust has not yet propagated."""
    deadline = time.monotonic() + timeout_s
    last_cause = None
    while time.monotonic() < deadline:
        resp = sfn.start_sync_execution(stateMachineArn=sm_arn, input="{}")
        if resp["status"] == "FAILED" and "is not authorized to assume" in (resp.get("cause") or ""):
            last_cause = resp.get("cause")
            time.sleep(4.0)
            continue
        return resp
    raise AssertionError(f"StartSyncExecution kept failing the assume-role race: {last_cause!r}")


def _wait_terminal(sfn, exec_arn: str, timeout_s: float = 120.0, poll_s: float = 2.0) -> dict:
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
