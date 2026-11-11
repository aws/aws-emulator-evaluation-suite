"""update-state-machine-cmk-add-swap-remove-reflected-in-describe."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-cmk-add-swap-remove-reflected-in-describe"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

_DEFINITION = json.dumps({"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}})

_STATES_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_OWNED = {"type": "AWS_OWNED_KEY"}


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


def _key(ctx, label: str) -> str:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-behav {CHECK[:180]} {label}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(_teardown(
        lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7)))
    return meta["Arn"]


def _exec_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnexec-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_STATES_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDenied while the fresh role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnupdcmk-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3.0)
            continue
        ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                                  "StateMachineDoesNotExist"))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 90s: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachine adds a customer-managed KMS key, swaps it for a different key and
    reuse period, then removes it back to AWS_OWNED_KEY; DescribeStateMachine reflects each
    change exactly and revisionId advances on every change.
    """
    sfn = ctx.client("stepfunctions")
    key1_arn = _key(ctx, "k1")
    key2_arn = _key(ctx, "k2")
    role_arn = _exec_role(ctx)
    arn = _create_state_machine(ctx, role_arn)

    initial = sfn.describe_state_machine(stateMachineArn=arn)
    assert initial.get("encryptionConfiguration") == _OWNED, (
        f"a freshly created state machine with no encryptionConfiguration must report "
        f"AWS_OWNED_KEY; got {initial.get('encryptionConfiguration')!r}")

    cmk1_cfg = {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key1_arn,
                "kmsDataKeyReusePeriodSeconds": 300}
    added = sfn.update_state_machine(stateMachineArn=arn, definition=_DEFINITION,
                                       encryptionConfiguration=cmk1_cfg)
    after_add = sfn.describe_state_machine(stateMachineArn=arn)
    assert after_add.get("encryptionConfiguration") == cmk1_cfg, (
        f"after adding the first CMK, DescribeStateMachine must report {cmk1_cfg!r}; got "
        f"{after_add.get('encryptionConfiguration')!r}")
    assert after_add.get("revisionId") == added.get("revisionId"), (
        f"DescribeStateMachine's revisionId {after_add.get('revisionId')!r} must equal the "
        f"UpdateStateMachine response's {added.get('revisionId')!r}")
    assert after_add.get("revisionId") not in (None, initial.get("revisionId")), (
        "adding a CMK must advance revisionId away from the pre-update value "
        f"{initial.get('revisionId')!r}; got {after_add.get('revisionId')!r}")

    cmk2_cfg = {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key2_arn,
                "kmsDataKeyReusePeriodSeconds": 600}
    swapped = sfn.update_state_machine(stateMachineArn=arn, definition=_DEFINITION,
                                         encryptionConfiguration=cmk2_cfg)
    after_swap = sfn.describe_state_machine(stateMachineArn=arn)
    assert after_swap.get("encryptionConfiguration") == cmk2_cfg, (
        f"after swapping to the second CMK, DescribeStateMachine must report {cmk2_cfg!r}; got "
        f"{after_swap.get('encryptionConfiguration')!r}")
    assert after_swap.get("revisionId") == swapped.get("revisionId") != after_add.get("revisionId"), (
        f"swapping CMKs must advance revisionId away from {after_add.get('revisionId')!r}; "
        f"got {after_swap.get('revisionId')!r}")

    removed = sfn.update_state_machine(stateMachineArn=arn, definition=_DEFINITION,
                                         encryptionConfiguration=_OWNED)
    after_remove = sfn.describe_state_machine(stateMachineArn=arn)
    assert after_remove.get("encryptionConfiguration") == _OWNED, (
        f"after removing the CMK, DescribeStateMachine must report AWS_OWNED_KEY with no "
        f"kmsKeyId; got {after_remove.get('encryptionConfiguration')!r}")
    assert after_remove.get("revisionId") == removed.get("revisionId") != after_swap.get("revisionId"), (
        f"removing the CMK must advance revisionId away from {after_swap.get('revisionId')!r}; "
        f"got {after_remove.get('revisionId')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
