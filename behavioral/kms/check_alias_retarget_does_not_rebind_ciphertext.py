"""alias-retarget-does-not-rebind-ciphertext."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "alias-retarget-does-not-rebind-ciphertext"
GROUP = 'aliases'
SERVICES = ['kms']

ERR_INCORRECT_KEY = "IncorrectKeyException"
ERR_NOT_FOUND = "NotFoundException"
MSG_INCORRECT_KEY = (
    "The key ID in the request does not identify a CMK that can perform this operation."
)
MSG_ALIAS_NOT_FOUND = "Alias {alias_arn} is not found."


def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _alias_resolves(kms, alias: str) -> bool:
    """True once DescribeKey resolves the alias, False while it answers NotFoundException."""
    try:
        kms.describe_key(KeyId=alias)
    except kms.exceptions.NotFoundException:
        return False
    return True


def _delete_alias_if_present(kms, alias: str) -> None:
    """Teardown: the check deletes the alias itself in its last phase, so NotFound is benign."""
    try:
        kms.delete_alias(AliasName=alias)
    except kms.exceptions.NotFoundException:
        pass


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is true; raise AssertionError on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window; bills until then)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Retargeting an alias changes which key new Encrypts use, but a ciphertext stays bound to
    its key: decrypting it via the retargeted alias raises IncorrectKeyException, while Decrypt
    with no KeyId still succeeds (alias retargeting is the manual key-rotation procedure).
    """
    kms = ctx.client("kms")
    key_a = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-aliasret-a-"),
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda _a=key_a: _teardown_key(kms, _a))
    key_b = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-aliasret-b-"),
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda _b=key_b: _teardown_key(kms, _b))
    assert key_a != key_b, "the two minted CMKs must be distinct — the invariant needs two keys"

    alias = "alias/" + ctx.unique_name("sim2real-behav-kms-ret-")
    assert not alias.startswith("alias/aws/"), alias
    kms.create_alias(AliasName=alias, TargetKeyId=key_a)
    # A NotFound teardown is benign: the check deletes the alias itself in its last phase.
    ctx.on_cleanup(lambda: _delete_alias_if_present(kms, alias))

    plaintext = b"pre-rotation-row"

    # --- Full valid setup: alias resolves to A, and an Encrypt through the alias reports A.
    _poll_until(
        lambda: _alias_resolves(kms, alias),
        lambda resolved: resolved,
        timeout_s=60,
        description="the new alias to resolve",
    )
    resolved_a = kms.describe_key(KeyId=alias)["KeyMetadata"]["Arn"]
    assert resolved_a == key_a, f"alias must resolve to key A right after creation, got {resolved_a!r}"
    enc_a = kms.encrypt(KeyId=alias, Plaintext=plaintext)
    ct_a = enc_a["CiphertextBlob"]
    assert enc_a["KeyId"] == key_a, (
        f"Encrypt via the alias must report the resolved key ARN, got {enc_a['KeyId']!r}"
    )

    # --- Break exactly one thing: retarget the alias to B. No ciphertext is touched.
    kms.update_alias(AliasName=alias, TargetKeyId=key_b)
    _poll_until(
        lambda: kms.describe_key(KeyId=alias)["KeyMetadata"]["Arn"],
        lambda arn: arn == key_b,
        timeout_s=60,
        description="the alias to resolve to key B",
    )
    enc_b = kms.encrypt(KeyId=alias, Plaintext=plaintext)
    ct_b = enc_b["CiphertextBlob"]
    assert enc_b["KeyId"] == key_b, enc_b["KeyId"]

    # --- The old ciphertext is bound to A, not to the alias. With no KeyId, KMS reads the
    # binding out of the blob and must return A.
    dec_a = kms.decrypt(CiphertextBlob=ct_a)
    assert dec_a["Plaintext"] == plaintext, "the pre-retarget ciphertext must still decrypt"
    assert dec_a["KeyId"] == key_a, (
        f"the ciphertext is bound to the key that produced it; Decrypt reported "
        f"{dec_a['KeyId']!r}, expected {key_a!r}"
    )

    # --- And naming the alias explicitly must be REFUSED, because the alias now resolves to a
    # key that did not produce this ciphertext.
    got = _err(lambda: kms.decrypt(CiphertextBlob=ct_a, KeyId=alias))
    assert got == (ERR_INCORRECT_KEY, MSG_INCORRECT_KEY), (
        f"Decrypt of A's ciphertext with KeyId={alias} (now -> B) must raise "
        f"{ERR_INCORRECT_KEY} {MSG_INCORRECT_KEY!r}, got {got!r}"
    )
    # Same refusal when B's ARN is named directly — the alias is not the special case, the key is.
    got = _err(lambda: kms.decrypt(CiphertextBlob=ct_a, KeyId=key_b))
    assert got == (ERR_INCORRECT_KEY, MSG_INCORRECT_KEY), (
        f"Decrypt of A's ciphertext with B's ARN must raise {ERR_INCORRECT_KEY} "
        f"{MSG_INCORRECT_KEY!r}, got {got!r}"
    )

    # --- Effect absent: the two refusals damaged neither blob, and both keys still work.
    control_a = kms.decrypt(CiphertextBlob=ct_a, KeyId=key_a)["Plaintext"]
    assert control_a == plaintext, f"the refusal above must not have damaged ct_a; got {control_a!r}"
    dec_b = kms.decrypt(CiphertextBlob=ct_b, KeyId=alias)
    assert dec_b["Plaintext"] == plaintext, (
        f"the refusal above must not have damaged ct_b; got {dec_b['Plaintext']!r}"
    )
    assert dec_b["KeyId"] == key_b, dec_b["KeyId"]

    # --- Restore: retarget the alias back to A. The identical call that raised
    # IncorrectKeyException above must now succeed — the refusal tracks the alias's *current*
    # target, not a sticky failure remembered for this ciphertext.
    kms.update_alias(AliasName=alias, TargetKeyId=key_a)
    _poll_until(
        lambda: kms.describe_key(KeyId=alias)["KeyMetadata"]["Arn"],
        lambda arn: arn == key_a,
        timeout_s=60,
        description="the alias to resolve back to key A",
    )
    restored = kms.decrypt(CiphertextBlob=ct_a, KeyId=alias)
    assert restored["Plaintext"] == plaintext, (
        f"after retargeting the alias back to A, Decrypt(ct_a, KeyId={alias}) must succeed, "
        f"got Plaintext={restored['Plaintext']!r}"
    )
    assert restored["KeyId"] == key_a, (
        f"after retargeting the alias back to A, Decrypt(ct_a, KeyId={alias}) must report "
        f"{key_a!r}, got {restored['KeyId']!r}"
    )

    # Retarget forward to B again so the delete-alias phase below still exercises alias -> B.
    kms.update_alias(AliasName=alias, TargetKeyId=key_b)
    _poll_until(
        lambda: kms.describe_key(KeyId=alias)["KeyMetadata"]["Arn"],
        lambda arn: arn == key_b,
        timeout_s=60,
        description="the alias to resolve to key B again",
    )

    # --- Deleting the alias removes only the pointer: Encrypt by that name now fails, but both
    # ciphertexts remain decryptable under their own keys.
    kms.delete_alias(AliasName=alias)
    _poll_until(
        lambda: _alias_resolves(kms, alias),
        lambda resolved: not resolved,
        timeout_s=60,
        description="the deleted alias to stop resolving",
    )
    alias_arn = f"arn:aws:kms:{ctx.region}:{ctx.account}:{alias}"
    got = _err(lambda: kms.encrypt(KeyId=alias, Plaintext=plaintext))
    expected = (ERR_NOT_FOUND, MSG_ALIAS_NOT_FOUND.format(alias_arn=alias_arn))
    assert got == expected, f"Encrypt via a deleted alias must raise {expected!r}, got {got!r}"
    remaining_aliases = {a["AliasName"] for a in kms.list_aliases(KeyId=key_b)["Aliases"]}
    assert alias not in remaining_aliases, (
        f"deleted alias {alias!r} must not appear in ListAliases(KeyId={key_b}), saw {remaining_aliases!r}"
    )

    # --- Control: both keys are Enabled and both ciphertexts still round-trip.
    for key_arn, ct in ((key_a, ct_a), (key_b, ct_b)):
        state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
        assert state == "Enabled", f"key {key_arn} must remain Enabled, got {state!r}"
        rt = kms.decrypt(CiphertextBlob=ct, KeyId=key_arn)["Plaintext"]
        assert rt == plaintext, f"ciphertext for {key_arn} must still round-trip, got {rt!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
