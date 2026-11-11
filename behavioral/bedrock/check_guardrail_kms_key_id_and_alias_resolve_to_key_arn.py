"""guardrail-kms-key-id-and-alias-resolve-to-key-arn."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "guardrail-kms-key-id-and-alias-resolve-to-key-arn"
GROUP = "guardrails"
SERVICES = ["bedrock"]

_READY_TIMEOUT_S = 180


def _wait_ready(bc, gid):
    deadline = time.monotonic() + _READY_TIMEOUT_S
    status = None
    while time.monotonic() < deadline:
        status = bc.get_guardrail(guardrailIdentifier=gid)["status"]
        if status in ("READY", "FAILED"):
            break
        time.sleep(3)
    assert status == "READY", (
        f"guardrail {gid} never reached READY within {_READY_TIMEOUT_S}s; last status={status!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGuardrail reports kmsKeyArn as the key ARN given on create, and after UpdateGuardrail with
    the key's alias ARN it resolves to the same underlying key ARN, not the alias ARN.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_UpdateGuardrail.html
    """
    bc = ctx.client("bedrock")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-grkms-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    alias_name = ctx.unique_name("alias/sim2real-behav-grkms-")
    kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    ctx.on_cleanup(lambda: kms.delete_alias(AliasName=alias_name))
    alias_arn = f"arn:aws:kms:{ctx.region}:{account}:{alias_name}"

    # Full ARNs only: the service rejects a bare key id or "alias/<name>" that its model allows.
    name = ctx.unique_name("sim2real-behav-grkms-")
    create_resp = bc.create_guardrail(
        name=name,
        blockedInputMessaging="Input blocked by guardrail.",
        blockedOutputsMessaging="Output blocked by guardrail.",
        kmsKeyId=key_arn,
        wordPolicyConfig={"wordsConfig": [{"text": "sim2real-grkms-blockedword"}]},
    )
    gid = create_resp["guardrailId"]
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=gid))

    _wait_ready(bc, gid)

    after_create = bc.get_guardrail(guardrailIdentifier=gid)
    assert after_create.get("kmsKeyArn") == key_arn, (
        f"GetGuardrail after CreateGuardrail(kmsKeyId={key_arn!r}) must echo kmsKeyArn as "
        f"the same key ARN; got {after_create.get('kmsKeyArn')!r}"
    )

    bc.update_guardrail(
        guardrailIdentifier=gid,
        name=name,
        blockedInputMessaging="Input blocked by guardrail.",
        blockedOutputsMessaging="Output blocked by guardrail.",
        kmsKeyId=alias_arn,
        wordPolicyConfig={"wordsConfig": [{"text": "sim2real-grkms-blockedword"}]},
    )

    after_update = bc.get_guardrail(guardrailIdentifier=gid)
    assert after_update.get("kmsKeyArn") == key_arn, (
        f"GetGuardrail after UpdateGuardrail(kmsKeyId={alias_arn!r}) must resolve to the "
        f"SAME underlying key ARN {key_arn!r} the alias targets, not the alias's own ARN "
        f"{alias_arn!r}; got {after_update.get('kmsKeyArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
