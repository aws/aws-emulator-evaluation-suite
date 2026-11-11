"""update-state-machine-encryption-configuration-without-definition-missing-required-parameter."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-encryption-configuration-without-definition-missing-required-parameter"
GROUP = "state_machine_lifecycle"
SERVICES = ["stepfunctions"]

_DEFINITION = json.dumps({"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}})

_STATES_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_MESSAGE = "The definition must be specified when updating the EncryptionConfiguration"


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


def _key(ctx) -> str:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-behav {CHECK[:180]}",
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
    name = ctx.unique_name("sim2real-behav-sfnupdenc-")
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachine with encryptionConfiguration but neither definition nor roleArn fails
    with the exact MissingRequiredParameter message and leaves the configuration unchanged,
    while the identical call naming a definition too succeeds and the change becomes visible.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _exec_role(ctx)
    arn = _create_state_machine(ctx, role_arn)
    key_arn = _key(ctx)

    before = sfn.describe_state_machine(stateMachineArn=arn)
    assert before.get("encryptionConfiguration") == {"type": "AWS_OWNED_KEY"}, (
        f"a freshly created state machine must report AWS_OWNED_KEY; got "
        f"{before.get('encryptionConfiguration')!r}")

    enc_cfg = {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
               "kmsDataKeyReusePeriodSeconds": 300}

    code, message = _error(lambda: sfn.update_state_machine(
        stateMachineArn=arn, encryptionConfiguration=enc_cfg))
    assert code == "MissingRequiredParameter", f"expected MissingRequiredParameter, got {code!r}"
    assert message == _MESSAGE, f"expected message {_MESSAGE!r}, got {message!r}"

    code2, message2 = _error(lambda: sfn.update_state_machine(
        stateMachineArn=arn, roleArn=role_arn, encryptionConfiguration=enc_cfg))
    assert code2 == "MissingRequiredParameter", (
        f"roleArn alone must not satisfy the definition requirement; expected "
        f"MissingRequiredParameter, got {code2!r}")
    assert message2 == _MESSAGE, f"expected message {_MESSAGE!r}, got {message2!r}"

    after_rejected = sfn.describe_state_machine(stateMachineArn=arn)
    assert after_rejected.get("encryptionConfiguration") == {"type": "AWS_OWNED_KEY"}, (
        "the rejected calls must leave the encryption configuration unchanged; got "
        f"{after_rejected.get('encryptionConfiguration')!r}")
    assert after_rejected.get("revisionId") == before.get("revisionId"), (
        f"the rejected calls must not advance revisionId: before "
        f"{before.get('revisionId')!r}, after {after_rejected.get('revisionId')!r}")

    # Positive control: the identical encryptionConfiguration, on the identical state machine,
    # naming a definition too, must succeed and the change must be visible via an independent read.
    sfn.update_state_machine(stateMachineArn=arn, definition=_DEFINITION, encryptionConfiguration=enc_cfg)
    after_accepted = sfn.describe_state_machine(stateMachineArn=arn)
    assert after_accepted.get("encryptionConfiguration") == enc_cfg, (
        f"the identical call naming a definition too must apply the encryptionConfiguration; "
        f"got {after_accepted.get('encryptionConfiguration')!r}")
    assert after_accepted.get("revisionId") != before.get("revisionId"), (
        "the accepted update must advance revisionId away from "
        f"{before.get('revisionId')!r}; got {after_accepted.get('revisionId')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
