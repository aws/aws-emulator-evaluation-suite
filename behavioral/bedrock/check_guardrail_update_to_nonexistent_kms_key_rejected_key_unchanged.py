"""guardrail-update-to-nonexistent-kms-key-rejected-key-unchanged."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guardrail-update-to-nonexistent-kms-key-rejected-key-unchanged"
GROUP = "guardrails"
SERVICES = ["bedrock", "kms"]

_INVALID_KMS_KEY = ("ValidationException", "The kmsKeyId provided is invalid.")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _list_guardrail_names(bc) -> set:
    names = set()
    token = None
    while True:
        kw = {"maxResults": 100}
        if token:
            kw["nextToken"] = token
        page = bc.list_guardrails(**kw)
        names.update(g["name"] for g in page.get("guardrails") or [])
        token = page.get("nextToken")
        if not token:
            break
    return names


def _delete_guardrail(bc, gid, timeout_s: float = 50.0) -> None:
    """Delete a guardrail and wait until it reads as gone, so its KMS key is retired after it."""
    bc.delete_guardrail(guardrailIdentifier=gid)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:  # the guardrail deletes in the background
        try:
            bc.get_guardrail(guardrailIdentifier=gid)
        except bc.exceptions.ResourceNotFoundException:
            return
        time.sleep(3)
    raise AssertionError(f"guardrail {gid} still present {timeout_s}s after its delete")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGuardrail with a nonexistent KMS key ARN is rejected and creates nothing, the
    identical request with a real customer-managed key succeeds and reports that key's ARN, and
    UpdateGuardrail to a nonexistent key ARN is rejected with the stored key and updatedAt intact.
    """
    bc = ctx.client("bedrock")
    kms = ctx.client("kms")

    nonexistent_key_arn = f"arn:aws:kms:{ctx.region}:{ctx.account}:key/{uuid.uuid4()}"
    word_policy = {"wordsConfig": [{"text": "sim2real-grkmsupd-blockedword"}]}

    rejected_name = ctx.unique_name("sim2real-behav-grkmsupd-rej-")
    code, message = _error(lambda: bc.create_guardrail(
        name=rejected_name,
        blockedInputMessaging="Input blocked by guardrail.",
        blockedOutputsMessaging="Output blocked by guardrail.",
        kmsKeyId=nonexistent_key_arn,
        wordPolicyConfig=word_policy,
    ))
    assert (code, message) == _INVALID_KMS_KEY, (
        f"expected {_INVALID_KMS_KEY!r} for CreateGuardrail with a well-formed but nonexistent "
        f"kmsKeyId ARN, got {(code, message)!r}"
    )
    assert rejected_name not in _list_guardrail_names(bc), (
        f"the rejected CreateGuardrail({rejected_name!r}) must not have created a guardrail, "
        f"but a guardrail named {rejected_name!r} is listed"
    )

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-grkmsupd-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    name = ctx.unique_name("sim2real-behav-grkmsupd-")
    created = bc.create_guardrail(
        name=name,
        blockedInputMessaging="Input blocked by guardrail.",
        blockedOutputsMessaging="Output blocked by guardrail.",
        kmsKeyId=key_arn,
        wordPolicyConfig=word_policy,
    )
    gid = created["guardrailId"]
    ctx.on_cleanup(lambda: _delete_guardrail(bc, gid))

    after_create = bc.get_guardrail(guardrailIdentifier=gid)
    assert after_create["kmsKeyArn"] == key_arn, (
        f"GetGuardrail after CreateGuardrail(kmsKeyId={key_arn!r}) must report that key's ARN; "
        f"got {after_create.get('kmsKeyArn')!r}"
    )
    original_updated_at = after_create["updatedAt"]

    code, message = _error(lambda: bc.update_guardrail(
        guardrailIdentifier=gid,
        name=name,
        blockedInputMessaging="Input blocked by guardrail.",
        blockedOutputsMessaging="Output blocked by guardrail.",
        kmsKeyId=nonexistent_key_arn,
        wordPolicyConfig=word_policy,
    ))
    assert (code, message) == _INVALID_KMS_KEY, (
        f"expected {_INVALID_KMS_KEY!r} for UpdateGuardrail with a well-formed but nonexistent "
        f"kmsKeyId ARN, got {(code, message)!r}"
    )

    after_update = bc.get_guardrail(guardrailIdentifier=gid)
    assert after_update["kmsKeyArn"] == key_arn, (
        f"the rejected UpdateGuardrail(kmsKeyId={nonexistent_key_arn!r}) must leave the stored "
        f"key untouched ({key_arn!r}); got {after_update.get('kmsKeyArn')!r}"
    )
    assert after_update["updatedAt"] == original_updated_at, (
        f"the rejected UpdateGuardrail must not move updatedAt from {original_updated_at!r}; "
        f"got {after_update['updatedAt']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
