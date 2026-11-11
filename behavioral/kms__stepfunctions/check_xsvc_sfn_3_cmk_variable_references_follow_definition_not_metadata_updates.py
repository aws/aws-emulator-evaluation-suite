"""xsvc-sfn-3-cmk-variable-references-follow-definition-not-metadata-updates."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-3-cmk-variable-references-follow-definition-not-metadata-updates"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]


@tags("axis:happy-path", "plane:control", "cap:c3", "concern:representation")
def run(ctx) -> None:
    """On a CMK-encrypted state machine, UpdateStateMachine with a new JSONata definition
    recomputes variableReferences for the new states; a metadata-only update (swapping roleArn,
    no definition) leaves variableReferences exactly as the last definition produced.
    """
    sfn = ctx.client("stepfunctions")
    key = _key(ctx)
    _n1, role1 = _exec_role(ctx, key["Arn"])
    _n2, role2 = _exec_role(ctx, key["Arn"])
    arn = _state_machine(ctx, role1, key["Arn"], _DEF_V1)

    refs1 = sfn.describe_state_machine(stateMachineArn=arn).get("variableReferences")
    assert refs1 == {"UseA": ["a"]}, (
        f"a fresh CMK JSONata machine must report variableReferences for its own definition; "
        f"got {refs1!r}")

    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(_DEF_V2))
    _wait_revision(ctx, arn, "UseBC")
    refs2 = sfn.describe_state_machine(stateMachineArn=arn).get("variableReferences")
    assert refs2 is not None and sorted(refs2.get("UseBC", [])) == ["b", "c"], (
        f"UpdateStateMachine with a new definition must recompute variableReferences for the "
        f"new states; got {refs2!r}")
    assert "UseA" not in refs2, (
        f"the old definition's state must not survive in variableReferences; got {refs2!r}")

    sfn.update_state_machine(stateMachineArn=arn, roleArn=role2)
    deadline = time.monotonic() + 60.0
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_state_machine(stateMachineArn=arn)
        if desc["roleArn"] == role2:
            break
        time.sleep(2.0)
    assert desc is not None and desc["roleArn"] == role2, (
        f"DescribeStateMachine must report the swapped roleArn after a metadata-only update; "
        f"got {desc and desc.get('roleArn')!r}")
    refs3 = desc.get("variableReferences")
    assert refs3 == refs2, (
        f"a metadata-only update (roleArn only, no definition) must leave variableReferences "
        f"exactly as the last definition produced: before {refs2!r}, after {refs3!r}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# V1 assigns "a" in Init and reads it in UseA: variableReferences = {"UseA": ["a"]}.
_DEF_V1 = {
    "QueryLanguage": "JSONata",
    "StartAt": "Init",
    "States": {
        "Init": {"Type": "Pass", "Assign": {"a": 1}, "Next": "UseA"},
        "UseA": {"Type": "Pass", "Output": {"val": "{% $a %}"}, "End": True},
    },
}

# V2 assigns "b" and "c" and reads both in UseBC: variableReferences = {"UseBC": ["b", "c"]}.
_DEF_V2 = {
    "QueryLanguage": "JSONata",
    "StartAt": "Init2",
    "States": {
        "Init2": {"Type": "Pass", "Assign": {"b": 2, "c": 3}, "Next": "UseBC"},
        "UseBC": {"Type": "Pass", "Output": {"sum": "{% $b + $c %}"}, "End": True},
    },
}

_REUSE_S = 60


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-xsvc-sfn3 {CHECK[:200]}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _exec_role(ctx, key_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfn3-kms-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn CMK execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="kms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
             "Resource": key_arn}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="kms"))
    return name, arn


def _state_machine(ctx, role_arn: str, key_arn: str, definition: dict) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfn3-kms-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                encryptionConfiguration={
                    "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
                    "kmsDataKeyReusePeriodSeconds": _REUSE_S,
                },
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


def _wait_revision(ctx, arn: str, want_state: str) -> None:
    """Poll until DescribeStateMachine reflects the new definition (UpdateStateMachine is async)."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 60.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_state_machine(stateMachineArn=arn)
        if want_state in json.loads(last["definition"]).get("States", {}):
            return
        time.sleep(2.0)
    raise AssertionError(
        f"DescribeStateMachine still shows the old definition {60}s after UpdateStateMachine; "
        f"got {last and last.get('definition')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
